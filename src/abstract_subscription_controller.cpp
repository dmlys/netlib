#include <ext/net/abstract_subscription_controller.hpp>

namespace ext {
namespace net
{
	BOOST_NORETURN void abstract_subscription_controller::on_bad_request()
	{
		throw std::logic_error("abstract_subscription_controller: bad request");
	}

	inline void abstract_subscription_controller::on_unexpected(state_type ev)
	{
		
	}

	void abstract_subscription_controller::emit_signal(signal_type & sig, state_type state)
	{
		sig(state);
	}

	template <class State>
	inline static void set_result(State & state, bool success, std::exception_ptr eptr)
	{
		if (not state or state->is_ready()) return;

		if (success)
			state->set_value(true);
		else if (eptr == nullptr)
			state->set_value(false);
		else
			state->set_exception(std::move(eptr));
	}

	template <class State>
	inline static void abandoned_request(State & state, bool counterpart_success)
	{
		if (not counterpart_success and state and state->is_pending())
		{
			state->set_value(false);
			//state->release_promise();
		}
	}

	ext::shared_future<void> abstract_subscription_controller::do_close(unique_lock & lk)
	{
		assert(lk.owns_lock());
		switch (m_state)
		{
			case opened:
			case paused:
			case pausing:
			case resuming:
				m_state = closing;
				m_close_future = ext::make_intrusive<ext::shared_state<void>>();
				m_close_future->mark_uncancellable();
				
				do_close_request(std::move(lk));
				return {m_close_future};

			case closed:
			case closing:
			default:
				return {m_close_future};
		}
	}

	ext::shared_future<bool> abstract_subscription_controller::do_pause(unique_lock & lk)
	{
		assert(lk.owns_lock());
		switch (m_state)
		{
			case opened:
				m_state = pausing;
				m_pause_future = ext::make_intrusive<ext::shared_state<bool>>();
				m_pause_future->mark_uncancellable();

				do_pause_request(std::move(lk));
				return {m_pause_future};

			case resuming:
				on_bad_request();

			case closed:
			case closing:
			case paused:
			case pausing:
			default:
				return {m_pause_future};

		}
	}

	ext::shared_future<bool> abstract_subscription_controller::do_resume(unique_lock & lk)
	{
		assert(lk.owns_lock());
		switch (m_state)
		{
			case paused:
				m_state = resuming;
				m_resume_future = ext::make_intrusive<ext::shared_state<bool>>();
				m_resume_future->mark_uncancellable();

				do_resume_request(std::move(lk));
				return {m_resume_future};

			case pausing:
				on_bad_request();

			case opened:
			case resuming:
			case closed:
			case closing:
			default:
				return {m_resume_future};
		}
	}

	void abstract_subscription_controller::notify_closed(unique_lock lk)
	{
		assert(lk.owns_lock());
		auto fclosed = m_close_future;
		auto fpaused = m_pause_future;
		auto fresumed = m_resume_future;

		switch (m_state)
		{
			case closed:
			case paused:
			case pausing:
			case resumed:
			case resuming:
				on_unexpected(closed);
				// fall through

			default:
				m_state = closed;
				lk.unlock();

				if (fclosed) fclosed->set_value();
				abandoned_request(fpaused, false);
				abandoned_request(fresumed, false);
				emit_signal(m_event_signal, closed);
				return;
		}
	}

	void abstract_subscription_controller::notify_paused(unique_lock lk, bool success, std::exception_ptr eptr)
	{
		assert(lk.owns_lock());
		auto fpaused  = m_pause_future;
		auto fresumed = m_resume_future;
		
		switch (m_state)
		{
			case closed:
			case closing:
				on_unexpected(paused);
				return;

			case opened:
			case paused:
			case resuming:
				on_unexpected(paused);
				// fall through

			case pausing:
				m_state = paused;
				lk.unlock();

				set_result(fpaused, success, std::move(eptr));
				abandoned_request(fresumed, success);
				emit_signal(m_event_signal, paused);
				return;
		}
	}

	void abstract_subscription_controller::notify_resumed(unique_lock lk, bool success, std::exception_ptr eptr)
	{
		assert(lk.owns_lock());
		auto fresumed = m_resume_future;
		auto fpaused  = m_pause_future;
		
		switch (m_state)
		{
			case closed:
			case closing:
				on_unexpected(resumed);
				return;

			case opened:
			case paused:
			case pausing:
				on_unexpected(resumed);

			case resuming:
				m_state = opened;
				lk.unlock();

				set_result(fresumed, success, std::move(eptr));
				abandoned_request(fpaused, success);
				emit_signal(m_event_signal, resumed);
				return;
		}
	}

	abstract_subscription_controller::state_type abstract_subscription_controller::get_state()
	{
		unique_lock lk(m_mutex);
		return m_state;
	}

	ext::shared_future<void> abstract_subscription_controller::close()
	{
		unique_lock lk(m_mutex);
		return do_close(lk);
	}

	ext::shared_future<bool> abstract_subscription_controller::pause()
	{
		unique_lock lk(m_mutex);
		return do_pause(lk);
	}

	ext::shared_future<bool> abstract_subscription_controller::resume()
	{
		unique_lock lk(m_mutex);
		return do_resume(lk);
	}

	abstract_subscription_controller::abstract_subscription_controller() = default;

	abstract_subscription_controller::~abstract_subscription_controller() noexcept
	{
		if (m_close_future)  m_close_future->release_promise();
		if (m_pause_future)  m_pause_future->release_promise();
		if (m_resume_future) m_resume_future->release_promise();
	}

}}
