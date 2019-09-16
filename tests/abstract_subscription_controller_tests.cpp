#include <boost/test/unit_test.hpp>
#include <ext/net/abstract_subscription_controller.hpp>

namespace
{
	class test_subscription_controller : public ext::net::abstract_subscription_controller
	{
		// abstract_subscription_controller interface
	protected:
		virtual void do_close_request(unique_lock lk) override {}
		virtual void do_pause_request(unique_lock lk) override {}
		virtual void do_resume_request(unique_lock lk) override {}

	public:
		void complete_close_request(std::exception_ptr eptr = nullptr) { notify_closed(unique_lock(m_mutex), std::move(eptr)); }
		void complete_pause_request(bool success = true, std::exception_ptr eptr = nullptr) { notify_paused(unique_lock(m_mutex), success, std::move(eptr)); }
		void complete_resume_request(bool success = true, std::exception_ptr eptr = nullptr) { notify_resumed(unique_lock(m_mutex), success, std::move(eptr)); }

		auto get_delayed_state() const { return m_delayed_state; }
	};

	using state_type   = test_subscription_controller::state_type;
	using delayed_type = test_subscription_controller::delayed_state_type;
}


BOOST_AUTO_TEST_SUITE(abstract_subscription_controller_tests)

BOOST_AUTO_TEST_CASE(basic)
{
	test_subscription_controller subscription;

	ext::shared_future<bool> pause_future, resume_future;

	BOOST_CHECK_EQUAL(subscription.get_state(), state_type::opened);
	BOOST_CHECK_EQUAL(subscription.get_delayed_state(), delayed_type::normal);

	// resume on opened subscription is noop
	resume_future = subscription.resume();
	BOOST_CHECK_EQUAL(subscription.get_state(), state_type::opened);
	BOOST_CHECK_EQUAL(resume_future.get(), true);

	pause_future = subscription.pause();
	BOOST_CHECK_EQUAL(subscription.get_state(), state_type::pausing);
	BOOST_CHECK(pause_future.is_pending());

	{
		auto pr1 = subscription.pause();
		auto pr2 = subscription.pause();

		BOOST_CHECK(pause_future.handle() == pr1.handle() and pr1.handle() == pr2.handle());
		BOOST_CHECK(pause_future.is_pending());

		BOOST_CHECK(subscription.get_state() == state_type::pausing);
	}

	subscription.complete_pause_request();
	BOOST_CHECK_EQUAL(pause_future.get(), true);
	BOOST_CHECK_EQUAL(subscription.get_state(), state_type::paused);



	resume_future = subscription.resume();
	BOOST_CHECK_EQUAL(subscription.get_state(), state_type::resuming);
	BOOST_CHECK(resume_future.is_pending());

	{
		auto rr1 = subscription.resume();
		auto rr2 = subscription.resume();

		BOOST_CHECK(resume_future.handle() == rr1.handle() and rr1.handle() == rr2.handle());
		BOOST_CHECK(resume_future.is_pending());

		BOOST_CHECK(subscription.get_state() == state_type::resuming);
	}

	subscription.complete_resume_request();
	BOOST_CHECK_EQUAL(resume_future.get(), true);
	BOOST_CHECK_EQUAL(subscription.get_state(), state_type::opened);


	auto close_future = subscription.close();
	BOOST_CHECK(close_future.is_pending());
	BOOST_CHECK_EQUAL(subscription.get_state(), state_type::closing);

	// if started closing - nothing can be done
	subscription.pause();
	BOOST_CHECK_EQUAL(subscription.get_state(), state_type::closing);
	subscription.resume();
	BOOST_CHECK_EQUAL(subscription.get_state(), state_type::closing);
	subscription.close();
	BOOST_CHECK_EQUAL(subscription.get_state(), state_type::closing);

	subscription.complete_close_request();
	BOOST_CHECK_EQUAL(subscription.get_state(), state_type::closed);
	BOOST_CHECK(close_future.is_ready());

	// if closed - nothing can be done
	subscription.pause();
	BOOST_CHECK_EQUAL(subscription.get_state(), state_type::closed);
	subscription.resume();
	BOOST_CHECK_EQUAL(subscription.get_state(), state_type::closed);
	subscription.close();
	BOOST_CHECK_EQUAL(subscription.get_state(), state_type::closed);
}

BOOST_AUTO_TEST_CASE(events)
{
	test_subscription_controller subscription;

	std::vector<state_type> events;
	unsigned event_count = 0;

	auto catch_event = [&events](auto event) { events.push_back(event); };
	subscription.on_event(catch_event);

	ext::shared_future<bool> pause_future, resume_future;

	pause_future = subscription.pause();
	BOOST_CHECK(pause_future.is_pending());
	BOOST_CHECK_EQUAL(subscription.get_state(), state_type::pausing);


	subscription.complete_pause_request(true);

	BOOST_CHECK_EQUAL(pause_future.get(), true);
	BOOST_CHECK_EQUAL(events[event_count++], state_type::paused);
	BOOST_CHECK_EQUAL(subscription.get_state(), state_type::paused);

	subscription.complete_resume_request(true);
	BOOST_CHECK_EQUAL(events[event_count++], state_type::resumed);
	BOOST_CHECK_EQUAL(subscription.get_state(), state_type::resumed);


	subscription.complete_pause_request(false);
	BOOST_CHECK_EQUAL(events.size(), event_count);
	BOOST_CHECK_EQUAL(subscription.get_state(), state_type::resumed);

	subscription.complete_pause_request(true);
	BOOST_CHECK_EQUAL(events[event_count++], state_type::paused);
	BOOST_CHECK_EQUAL(subscription.get_state(), state_type::paused);
}

BOOST_AUTO_TEST_CASE(delayed)
{
	test_subscription_controller subscription;
	ext::shared_future<bool> pause_future, resume_future;


	// pause, but then without waiting for it to complete, issue resume request
	pause_future = subscription.pause();
	BOOST_CHECK_EQUAL(subscription.get_state(), state_type::pausing);
	BOOST_CHECK(pause_future.is_pending());

	resume_future = subscription.resume();
	// we are still in pausing state, and futures are pending
	BOOST_CHECK_EQUAL(subscription.get_state(), state_type::pausing);
	BOOST_CHECK(pause_future.is_pending());
	BOOST_CHECK(resume_future.is_pending());
	// but delayed state is want_resume
	BOOST_CHECK_EQUAL(subscription.get_delayed_state(), delayed_type::want_resume);

	// now when disconnect request is completed, subscription automatically starts issues connect
	subscription.complete_pause_request();

	BOOST_CHECK(pause_future.is_ready());
	BOOST_CHECK(resume_future.is_pending());
	BOOST_CHECK_EQUAL(subscription.get_state(), state_type::resuming);
	// delayed state returned to normal
	BOOST_CHECK_EQUAL(subscription.get_delayed_state(), delayed_type::normal);

	subscription.complete_resume_request();
	BOOST_CHECK_EQUAL(subscription.get_state(), state_type::resumed);
	BOOST_CHECK_EQUAL(subscription.get_delayed_state(), delayed_type::normal);
	BOOST_CHECK_EQUAL(resume_future.get(), true);




	// pause, resume, pause
	pause_future = subscription.pause();
	resume_future = subscription.resume();
	resume_future = subscription.resume();

	BOOST_CHECK_EQUAL(subscription.get_state(), state_type::pausing);
	BOOST_CHECK_EQUAL(subscription.get_delayed_state(), delayed_type::want_resume);
	BOOST_CHECK(pause_future.is_pending());
	BOOST_CHECK(resume_future.is_pending());

	pause_future = subscription.pause();
	BOOST_CHECK_EQUAL(subscription.get_state(), state_type::pausing);
	BOOST_CHECK_EQUAL(subscription.get_delayed_state(), delayed_type::normal);
	BOOST_CHECK(pause_future.is_pending());

	//BOOST_CHECK(connect_future.is_cancelled());
	BOOST_CHECK_EQUAL(resume_future.get(), false);

	subscription.complete_pause_request();
	BOOST_CHECK_EQUAL(subscription.get_state(), state_type::paused);
	BOOST_CHECK_EQUAL(subscription.get_delayed_state(), delayed_type::normal);
	BOOST_CHECK(pause_future.is_ready());



	// resume, pause, resume
	resume_future = subscription.resume();
	pause_future = subscription.pause();
	pause_future = subscription.pause();

	BOOST_CHECK_EQUAL(subscription.get_state(), state_type::resuming);
	BOOST_CHECK_EQUAL(subscription.get_delayed_state(), delayed_type::want_pause);
	BOOST_CHECK(resume_future.is_pending());
	BOOST_CHECK(pause_future.is_pending());

	resume_future = subscription.resume();
	BOOST_CHECK_EQUAL(subscription.get_state(), state_type::resuming);
	BOOST_CHECK_EQUAL(subscription.get_delayed_state(), delayed_type::normal);
	BOOST_CHECK(resume_future.is_pending());

	//BOOST_CHECK(connect_future.is_cancelled());
	BOOST_CHECK_EQUAL(pause_future.get(), false);

	subscription.complete_resume_request();
	BOOST_CHECK_EQUAL(subscription.get_state(), state_type::resumed);
	BOOST_CHECK_EQUAL(subscription.get_delayed_state(), delayed_type::normal);
	BOOST_CHECK(resume_future.is_ready());
}

BOOST_AUTO_TEST_SUITE_END()
