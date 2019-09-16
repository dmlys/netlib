#include <ext/net/abstract_subscription_controller.hpp>

#include <fmt/format.h>
#include <ext/library_logger/logging_macros.hpp>

namespace ext {
namespace net
{
	inline void BOOST_NORETURN abstract_subscription_controller::on_bad_transaction()
	{
		throw std::logic_error("abstract_subscription_controller: bad transition");
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
	inline static void set_result(State & state, std::exception_ptr eptr)
	{
		if (not state or state->is_ready()) return;

		if (eptr == nullptr)
			state->set_value();
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

	template <class State>
	inline static auto & prepare_state(ext::intrusive_ptr<State> & state_ptr)
	{
		if (not state_ptr or state_ptr->is_ready())
		{
			state_ptr = ext::make_intrusive<State>();
			state_ptr->mark_uncancellable();
		}

		return state_ptr;
	}


	ext::shared_future<void> abstract_subscription_controller::do_close(unique_lock lk)
	{
		EXTLL_DEBUG_FMT(get_logger(), "Close request for {}; curstate = {}, delayed = {}", name(), state_string(m_state), delayed_string(m_delayed_state));

		assert(lk.owns_lock());
		decltype(m_resume_future) resume_future;
		decltype(m_pause_future)  pause_future;
		decltype(m_close_future)  close_future;

		switch (m_state)
		{
			case opened:
			case paused:
			case pausing:
			case resuming:
				m_close_future = ext::make_intrusive<ext::shared_state<void>>();
				m_close_future->mark_uncancellable();
				close_future = m_close_future;
				// pause and resume futures should be locked into false result
				pause_future = prepare_state(m_pause_future);
				resume_future = prepare_state(m_resume_future);

				m_state = closing;
				m_delayed_state = normal;

				try
				{
					do_close_request(std::move(lk));
				}
				catch (...)
				{
					notify_closed(unique_lock(m_mutex), std::current_exception());
				}

				set_result(pause_future, false, nullptr);
				set_result(resume_future, false, nullptr);

				return {std::move(close_future)};

			case closed:
			case closing:
			default:
				return {m_close_future};
		}
	}

	ext::shared_future<bool> abstract_subscription_controller::do_pause(unique_lock lk)
	{
		EXTLL_DEBUG_FMT(get_logger(), "Pause request for {}; curstate = {}, delayed = {}", name(), state_string(m_state), delayed_string(m_delayed_state));

		assert(lk.owns_lock());
		auto delayed_state = std::exchange(m_delayed_state, normal);
		decltype(m_resume_future) resume_future;
		decltype(m_pause_future)  pause_future;

		switch (m_state)
		{
			case resuming:
				assert(not m_pause_future or m_pause_future->is_ready() or delayed_state == want_pause);
				prepare_state(m_pause_future);
				m_delayed_state = want_pause;
				return {m_pause_future};

			case opened:
				assert(not m_pause_future or m_pause_future->is_ready() or delayed_state == want_pause);
				prepare_state(m_pause_future);
				pause_future = m_pause_future;
				m_state = pausing;
				m_delayed_state = normal;

				try
				{
					do_pause_request(std::move(lk));
				}
				catch (...)
				{
					notify_paused(unique_lock(m_mutex), false, std::current_exception());
				}

				return {std::move(pause_future)};

			case paused:
			case pausing:
				resume_future = m_resume_future;
				pause_future = m_pause_future;
				lk.unlock();
				if (delayed_state == want_resume)
					// this delayed resume future never had a chance
					set_result(resume_future, false, nullptr);

				return {std::move(pause_future)};

			case closed:
			case closing:
				return {m_pause_future};

			default:
				on_bad_transaction();

		}
	}

	ext::shared_future<bool> abstract_subscription_controller::do_resume(unique_lock lk)
	{
		EXTLL_DEBUG_FMT(get_logger(), "Resume request for {}; curstate = {}, delayed = {}", name(), state_string(m_state), delayed_string(m_delayed_state));

		assert(lk.owns_lock());
		auto delayed_state = std::exchange(m_delayed_state, normal);
		decltype(m_resume_future) resume_future;
		decltype(m_pause_future)  pause_future;

		switch (m_state)
		{
			case pausing:
				assert(not m_resume_future or m_resume_future->is_ready() or delayed_state == want_resume);
				prepare_state(m_resume_future);
				m_delayed_state = want_resume;
				return {m_resume_future};

			case paused:
				assert(not m_resume_future or m_resume_future->is_ready() or delayed_state == want_resume);
				prepare_state(m_resume_future);
				resume_future = m_resume_future;
				m_state = resuming;
				m_delayed_state = normal;

				try
				{
					do_resume_request(std::move(lk));
				}
				catch (...)
				{
					notify_resumed(unique_lock(m_mutex), false, std::current_exception());
				}

				return {std::move(resume_future)};

			case opened:
			case resuming:
				resume_future = m_resume_future;
				pause_future = m_pause_future;
				lk.unlock();
				if (delayed_state == want_pause)
					// this delayed pause future never had a chance
					set_result(pause_future, false, nullptr);

				return {std::move(resume_future)};

			case closed:
			case closing:
				return {m_resume_future};

			default:
				on_bad_transaction();
		}
	}

	void abstract_subscription_controller::notify_closed(unique_lock lk, std::exception_ptr eptr)
	{
		EXTLL_DEBUG_FMT(get_logger(), "Got closed notification for {}; curstate = {}, delayed = {}; eptr = {}",
		                name(), state_string(m_state), delayed_string(m_delayed_state), eptr ? "not null" : "null");

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
				m_delayed_state = normal;
				lk.unlock();

				assert(fclosed and fclosed->is_pending());
				set_result(fclosed, eptr);
				abandoned_request(fpaused, false);
				abandoned_request(fresumed, false);
				emit_signal(m_event_signal, closed);
				return;
		}
	}

	void abstract_subscription_controller::notify_paused(unique_lock lk, bool success, std::exception_ptr eptr)
	{
		EXTLL_DEBUG_FMT(get_logger(), "Got paused notification for {}; curstate = {}, delayed = {}; success = {}, eptr = {}",
		                name(), state_string(m_state), delayed_string(m_delayed_state), success, eptr ? "not null" : "null");

		assert(lk.owns_lock());
		auto fpaused  = m_pause_future;
		auto fresumed = m_resume_future;
		auto delayed_state = m_delayed_state;
		
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
				assert(m_delayed_state != want_pause);
				m_state = success ? paused : resumed;
				lk.unlock();

				set_result(fpaused, success, std::move(eptr));
				abandoned_request(fresumed, success);
				if (success)
					emit_signal(m_event_signal, paused);

				// if delayed resume
				if (delayed_state == want_resume)
				{
					lk.lock();
					// if still delayed resume(can be reset by pause/close between lk.unlock/lock)
					if (m_delayed_state == want_resume)
					{
						// m_delayed_state will be reset in do_resume
						do_resume(std::move(lk));
					}
				}

				return;
		}
	}

	void abstract_subscription_controller::notify_resumed(unique_lock lk, bool success, std::exception_ptr eptr)
	{
		EXTLL_DEBUG_FMT(get_logger(), "Got resumed notification for {}; curstate = {}, delayed = {}; success = {}, eptr = {}",
		                name(), state_string(m_state), delayed_string(m_delayed_state), success, eptr ? "not null" : "null");

		assert(lk.owns_lock());
		auto fresumed = m_resume_future;
		auto fpaused  = m_pause_future;
		auto delayed_state = m_delayed_state;
		
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
				assert(m_delayed_state != want_resume);
				m_state = success ? resumed : paused;
				lk.unlock();

				set_result(fresumed, success, std::move(eptr));
				abandoned_request(fpaused, success);
				if (success)
					emit_signal(m_event_signal, resumed);

				// if delayed pause
				if (delayed_state == want_pause)
				{
					lk.lock();
					// if still delayed pause(can be reset by resume/close between lk.unlock/lock)
					if (m_delayed_state == want_pause)
					{
						// m_delayed_state will be reset in do_pause
						do_pause(std::move(lk));
					}
				}

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
		return do_close(unique_lock(m_mutex));
	}

	ext::shared_future<bool> abstract_subscription_controller::pause()
	{
		return do_pause(unique_lock(m_mutex));
	}

	ext::shared_future<bool> abstract_subscription_controller::resume()
	{
		return do_resume(unique_lock(m_mutex));
	}

	abstract_subscription_controller::abstract_subscription_controller()
	{
		m_resume_future = ext::make_intrusive<ext::shared_state<bool>>();
		m_resume_future->set_value(true);
	}

	abstract_subscription_controller::~abstract_subscription_controller() noexcept
	{
		if (m_close_future)  m_close_future->release_promise();
		if (m_pause_future)  m_pause_future->release_promise();
		if (m_resume_future) m_resume_future->release_promise();
	}

}}
