#include <ext/net/abstract_connection_controller.hpp>

#include <fmt/format.h>
#include <ext/library_logger/logging_macros.hpp>

namespace ext {
namespace net
{
	BOOST_NORETURN void abstract_connection_controller::on_bad_transaction()
	{
		throw std::logic_error("abstract_connection_controller: bad transition");
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
	static void prepare_state(ext::intrusive_ptr<State> & state_ptr)
	{
		if (not state_ptr or state_ptr->is_ready())
		{
			state_ptr = ext::make_intrusive<State>();
			state_ptr->mark_uncancellable();
		}
	}

	void abstract_connection_controller::emit_signal(event_sig & sig, event_type ev)
	{
		sig(ev);
	}

	ext::shared_future<bool> abstract_connection_controller::do_connect(unique_lock lk)
	{
		EXTLL_DEBUG_FMT(m_logger, "Connect request for {}; curstate = {}, delayed = {}", name(), state_string(m_state), delayed_string(m_delayed_state));

		assert(lk.owns_lock());
		decltype(m_connect_future) connect_future;

		switch (m_state)
		{
		case online:
		case connecting:
			// connection is already executing - nothing to be done
			assert(m_delayed_state == normal);
			return {m_connect_future};

		case disconnecting:
			// connection request while disconnect - delay connect request
			assert(not m_connect_future or m_connect_future->is_ready() or m_delayed_state == want_connect);
			prepare_state(m_connect_future);
			m_delayed_state = want_connect;
			return {m_connect_future};

		case offline:
			assert(not m_connect_future or m_connect_future->is_ready() or m_delayed_state == want_connect);
			prepare_state(m_connect_future);
			connect_future = m_connect_future;
			m_state = connecting;
			m_delayed_state = normal;
			
			try
			{
				do_connect_request(std::move(lk));
			}
			catch (...)
			{
				EXTLL_ERROR_FMT(m_logger, "Connect request failed for {}", name());
				notify_connected(unique_lock(m_mutex), false, std::current_exception());
			}

			return {std::move(connect_future)};

		default:
			on_bad_transaction();
		}
	}

	ext::shared_future<void> abstract_connection_controller::do_disconnect(unique_lock lk)
	{
		EXTLL_DEBUG_FMT(m_logger, "Disconnect request for {}; curstate = {}, delayed = {}", name(), state_string(m_state), delayed_string(m_delayed_state));

		assert(lk.owns_lock());
		auto delayed_state = std::exchange(m_delayed_state, normal);
		decltype(m_disconnect_future) disconnect_future;
		decltype(m_connect_future)    connect_future;

		switch (m_state)
		{
		case offline:
		case disconnecting:
			disconnect_future = m_disconnect_future;
			connect_future = m_connect_future;
			lk.unlock();
			if (delayed_state == want_connect)
				// this delayed connect future never had a chance
				set_result(connect_future, false, nullptr);
				//connect_future->cancel();

			return {std::move(disconnect_future)};

		case online:
		case connecting:
			assert(delayed_state == normal);
			m_disconnect_future = ext::make_intrusive<ext::shared_state<void>>();
			m_disconnect_future->mark_uncancellable();
			disconnect_future = m_disconnect_future;
			m_state = disconnecting;

			try
			{
				do_disconnect_request(std::move(lk));
			}
			catch (...)
			{
				EXTLL_ERROR_FMT(m_logger, "Disconnect request failed for {}", name());
				notify_disconnected(unique_lock(m_mutex), std::current_exception());
			}

			return {std::move(disconnect_future)};

		default:
			on_bad_transaction();
		}
	}

	void abstract_connection_controller::notify_connected(unique_lock lk, bool success, std::exception_ptr eptr)
	{
		EXTLL_DEBUG_FMT(m_logger, "Got connected notification for {}; curstate = {}, delayed = {}; success = {}, eptr = {}",
		                name(), state_string(m_state), delayed_string(m_delayed_state), success, eptr ? "not null" : "null");

		assert(lk.owns_lock());
		auto connected = m_connect_future;
		
		switch (m_state)
		{
		case disconnecting:
			// It can happen that there was connection request - we started to connect,
			// next came disconnect request, it worked, and in parallel we've successfully connected.
			// Ignore that, next step we will disconnect.
			return;

		case connecting:
			assert(m_delayed_state == normal);
			m_state = success ? online : offline;
			lk.unlock();

			set_result(connected, success, std::move(eptr));
			if (success)
				emit_signal(m_event_signal, connection_controller::connected);
			else
			{
				emit_signal(m_event_signal, connection_controller::disconnected);
				emit_signal(m_event_signal, connection_controller::connection_error);
			}

			return;

		default:
			on_bad_transaction();
		}
	}

	void abstract_connection_controller::notify_disconnected(unique_lock lk, std::exception_ptr eptr)
	{
		EXTLL_DEBUG_FMT(m_logger, "Got disconnected notification for {}; curstate = {}, delayed = {}; eptr = {}",
		                name(), state_string(m_state), delayed_string(m_delayed_state), eptr ? "not null" : "null");

		assert(lk.owns_lock());
		auto connected = m_connect_future;
		auto disconnected = m_disconnect_future;
		auto delayed_state = m_delayed_state;

		switch (m_state)
		{
		case connecting:
			m_state = offline;
			lk.unlock();

			assert(delayed_state != want_connect);
			assert(disconnected->is_ready());
			set_result(connected, false, std::move(eptr));

			emit_signal(m_event_signal, connection_controller::disconnected);
			emit_signal(m_event_signal, connection_controller::connection_error);
			return;

		case disconnecting:
			m_state = offline;
			lk.unlock();

			if (delayed_state != want_connect)
				// if want_connect - we should not touch this future,
				// because connect operation not started, and this disconnect is not for this one
				set_result(connected, false, nullptr);

			set_result(disconnected, std::move(eptr));
			emit_signal(m_event_signal, connection_controller::disconnected);

			// if delayed connect
			if (delayed_state == want_connect)
			{
				lk.lock();
				// if still delayed connect(can be reset by disconnect between lk.unlock/lock)
				if (m_delayed_state == want_connect)
				{
					// m_delayed_state will be reset in do_connect
					do_connect(std::move(lk));
				}
			}

			return;

		case online:
			m_state = offline;
			lk.unlock();

			assert(connected->is_ready());
			assert(disconnected->is_ready());

			emit_signal(m_event_signal, connection_controller::disconnected);
			emit_signal(m_event_signal, connection_controller::connection_error);
			emit_signal(m_event_signal, connection_controller::connection_lost);
			return;

		default:
			on_bad_transaction();
		}
	}

	auto abstract_connection_controller::get_state() -> state_type
	{
		unique_lock lk(m_mutex);
		return m_state;
	}

	ext::shared_future<bool> abstract_connection_controller::connect()
	{
		return do_connect(unique_lock(m_mutex));
	}

	ext::shared_future<void> abstract_connection_controller::disconnect()
	{
		return do_disconnect(unique_lock(m_mutex));
	}

	abstract_connection_controller::abstract_connection_controller()
	{
		m_disconnect_future = ext::make_intrusive<ext::shared_state<void>>();
		m_disconnect_future->set_value();
	}

	abstract_connection_controller::~abstract_connection_controller() noexcept
	{
		if (m_connect_future)    m_connect_future->release_promise();
		if (m_disconnect_future) m_disconnect_future->release_promise();
	}
}}
