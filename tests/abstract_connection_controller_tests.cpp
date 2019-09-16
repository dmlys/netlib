#include <boost/test/unit_test.hpp>
#include <ext/net/abstract_connection_controller.hpp>

namespace
{
	class test_connection_controller : public ext::net::abstract_connection_controller
	{
		// abstract_connection_controller interface
	protected:
		virtual void do_connect_request(unique_lock lk) override {}
		virtual void do_disconnect_request(unique_lock lk) override {}

	public:
		void complete_connect_request(bool success = true, std::exception_ptr eptr = nullptr)    { notify_connected(unique_lock(m_mutex), success, std::move(eptr)); }
		void complete_disconnect_request(std::exception_ptr eptr = nullptr)                      { notify_disconnected(unique_lock(m_mutex), std::move(eptr)); }

		auto get_delayed_state() const { return m_delayed_state; }
	};

	using event_type   = test_connection_controller::event_type;
	using state_type   = test_connection_controller::state_type;
	using delayed_type = test_connection_controller::delayed_state_type;
}

BOOST_AUTO_TEST_SUITE(abstract_connection_controller_tests)

BOOST_AUTO_TEST_CASE(basic)
{
	test_connection_controller connection;

	ext::shared_future<bool> connect_future;
	ext::shared_future<void> disconnect_future;

	BOOST_CHECK(connection.get_state() == state_type::offline);
	BOOST_CHECK(connection.get_delayed_state() == delayed_type::normal);

	disconnect_future = connection.disconnect();
	BOOST_CHECK(disconnect_future.is_ready());

	connect_future = connection.connect();
	BOOST_CHECK(connect_future.is_pending());
	BOOST_CHECK(connection.get_state() == state_type::connecting);

	{
		auto cr1 = connection.connect();
		auto cr2 = connection.connect();

		BOOST_CHECK(connect_future.handle() == cr1.handle() and cr1.handle() == cr2.handle());
		BOOST_CHECK(connect_future.is_pending());

		BOOST_CHECK(connection.get_state() == state_type::connecting);
	}

	connection.complete_connect_request();
	BOOST_CHECK(connect_future.get() == true);
	BOOST_CHECK(connection.get_state() == state_type::online);

	connect_future = connection.connect();
	BOOST_CHECK(connect_future.get() == true);
	BOOST_CHECK(connection.get_state() == state_type::online);

	disconnect_future = connection.disconnect();
	BOOST_CHECK(disconnect_future.is_pending());
	BOOST_CHECK(connection.get_state() == state_type::disconnecting);

	{
		auto dr1 = connection.disconnect();
		auto dr2 = connection.disconnect();

		BOOST_CHECK(disconnect_future.handle() == dr1.handle() and dr1.handle() == dr2.handle());
		BOOST_CHECK(disconnect_future.is_pending());

		BOOST_CHECK(connection.get_state() == state_type::disconnecting);
	}

	connection.complete_disconnect_request();
	BOOST_CHECK(disconnect_future.is_ready());
	BOOST_CHECK(connection.get_state() == state_type::offline);


	// connect followed by disconnect case before connection completed
	connect_future = connection.connect();
	disconnect_future = connection.disconnect();
	BOOST_CHECK(connection.get_state() == state_type::disconnecting);
	BOOST_CHECK(connect_future.is_pending());
	BOOST_CHECK(disconnect_future.is_pending());

	connection.complete_connect_request();    // will be ignored - because we are disconnection
	BOOST_CHECK(connection.get_state() == state_type::disconnecting);

	connection.complete_disconnect_request();
	BOOST_CHECK(connection.get_state() == state_type::offline);

	BOOST_CHECK(connect_future.get() == false); // disconnect was issued, failed to connect in the end
	BOOST_CHECK(disconnect_future.is_ready());
}

BOOST_AUTO_TEST_CASE(events)
{
	test_connection_controller connection;

	std::vector<event_type> events;
	unsigned event_count = 0;

	auto catch_event = [&events](auto event) { events.push_back(event); };
	connection.on_event(catch_event);

	ext::shared_future<bool> connect_future;
	ext::shared_future<void> disconnect_future;

	connect_future = connection.connect();
	BOOST_CHECK(connect_future.is_pending());
	BOOST_CHECK_EQUAL(connection.get_state(), state_type::connecting);

	connection.complete_connect_request(true);

	BOOST_CHECK_EQUAL(connect_future.get(), true);
	BOOST_CHECK_EQUAL(events[event_count++], event_type::connected);


	// connection lost
	connection.complete_disconnect_request(std::make_exception_ptr(std::runtime_error("some_error")));
	BOOST_CHECK_EQUAL(connection.get_state(), state_type::offline);
	BOOST_CHECK_EQUAL(events[event_count++], event_type::disconnected);
	BOOST_CHECK_EQUAL(events[event_count++], event_type::connection_error);
	BOOST_CHECK_EQUAL(events[event_count++], event_type::connection_lost);

	connect_future = connection.connect();
	BOOST_CHECK_EQUAL(connection.get_state(), state_type::connecting);


	// error without exception
	connection.complete_connect_request(false, nullptr);
	BOOST_CHECK_EQUAL(connection.get_state(), state_type::offline);
	BOOST_CHECK_EQUAL(events[event_count++], event_type::disconnected);
	BOOST_CHECK_EQUAL(events[event_count++], event_type::connection_error);
	// no exception was provided
	BOOST_CHECK_EQUAL(connect_future.get(), false);


	// can't just become online, without request
	BOOST_CHECK_THROW(connection.complete_connect_request(), std::logic_error);
	BOOST_CHECK_EQUAL(connection.get_state(), state_type::offline);


	// connection error with exception
	connect_future = connection.connect();
	connection.complete_connect_request(false, std::make_exception_ptr(std::runtime_error("failure")));
	BOOST_CHECK_EQUAL(connection.get_state(), state_type::offline);
	BOOST_CHECK_EQUAL(events[event_count++], event_type::disconnected);
	BOOST_CHECK_EQUAL(events[event_count++], event_type::connection_error);
	// got exception
	BOOST_CHECK_THROW(connect_future.get(), std::runtime_error);
}


BOOST_AUTO_TEST_CASE(delayed)
{
	test_connection_controller connection;

	ext::shared_future<bool> connect_future;
	ext::shared_future<void> disconnect_future;

	connect_future = connection.connect();
	connection.complete_connect_request();
	BOOST_CHECK_EQUAL(connection.get_state(), state_type::online);
	BOOST_CHECK_EQUAL(connect_future.get(), true);



	// now we are connected

	// disconnect, but then without waiting for it to complete, issue another connect
	disconnect_future = connection.disconnect();
	BOOST_CHECK_EQUAL(connection.get_state(), state_type::disconnecting);
	BOOST_CHECK(disconnect_future.is_pending());

	connect_future = connection.connect();
	// we are still in disconnecting state, and futures are pending
	BOOST_CHECK_EQUAL(connection.get_state(), state_type::disconnecting);
	BOOST_CHECK(connect_future.is_pending());
	BOOST_CHECK(disconnect_future.is_pending());
	// but delayed state is want_connect
	BOOST_CHECK_EQUAL(connection.get_delayed_state(), delayed_type::want_connect);

	// now when disconnect request is completed, connection automatically starts issues connect
	connection.complete_disconnect_request();

	BOOST_CHECK(disconnect_future.is_ready());
	BOOST_CHECK(connect_future.is_pending());
	BOOST_CHECK_EQUAL(connection.get_state(), state_type::connecting);
	// delayed state returned to normal
	BOOST_CHECK_EQUAL(connection.get_delayed_state(), delayed_type::normal);

	connection.complete_connect_request();
	BOOST_CHECK_EQUAL(connection.get_state(), state_type::online);
	BOOST_CHECK_EQUAL(connection.get_delayed_state(), delayed_type::normal);
	BOOST_CHECK_EQUAL(connect_future.get(), true);




	// disconnect, connect, disconnect
	disconnect_future = connection.disconnect();
	connect_future = connection.connect();
	connect_future = connection.connect();

	BOOST_CHECK_EQUAL(connection.get_state(), state_type::disconnecting);
	BOOST_CHECK_EQUAL(connection.get_delayed_state(), delayed_type::want_connect);
	BOOST_CHECK(connect_future.is_pending());
	BOOST_CHECK(disconnect_future.is_pending());

	disconnect_future = connection.disconnect();
	BOOST_CHECK_EQUAL(connection.get_state(), state_type::disconnecting);
	BOOST_CHECK_EQUAL(connection.get_delayed_state(), delayed_type::normal);
	BOOST_CHECK(disconnect_future.is_pending());

	//BOOST_CHECK(connect_future.is_cancelled());
	BOOST_CHECK_EQUAL(connect_future.get(), false);

	connection.complete_disconnect_request();
	BOOST_CHECK_EQUAL(connection.get_state(), state_type::offline);
	BOOST_CHECK_EQUAL(connection.get_delayed_state(), delayed_type::normal);
	BOOST_CHECK(disconnect_future.is_ready());
}

BOOST_AUTO_TEST_SUITE_END()
