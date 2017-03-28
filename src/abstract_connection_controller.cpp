#include <ext/netlib/abstract_connection_controller.hpp>

namespace ext {
namespace netlib
{
	BOOST_NORETURN void abstract_connection_controller::on_bad_connect_request()
	{
		throw std::logic_error("abstract_connection_controller: bad connect request");
	}

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
	inline static void set_result(State & state)
	{
		if (not state or state->is_ready()) return;
		state->set_value();
	}

	void abstract_connection_controller::emit_signal(event_sig & sig, event_type ev)
	{
		sig(ev);
	}

	ext::shared_future<bool> abstract_connection_controller::do_connect(unique_lock & lk)
	{
		assert(lk.owns_lock());
		switch (m_state)
		{
		case disconnecting:
			/// connection request while disconnect request is not finished - is a logical error
			on_bad_connect_request();

		case offline:
			m_state = connecting;
			m_connect_future = ext::make_intrusive<ext::shared_state<bool>>();
			m_connect_future->mark_uncancellable();
			
			do_connect_request(std::move(lk));
			return m_connect_future;

		case online:
		case connecting:
			/// connection is already executing - nothing to be done
			return m_connect_future;

		default:
			on_bad_transaction();
		}
	}

	ext::shared_future<void> abstract_connection_controller::do_disconnect(unique_lock & lk)
	{
		assert(lk.owns_lock());
		switch (m_state)
		{
		case offline:
		case disconnecting:
			return m_disconnect_future;

		case online:
		case connecting:
			m_state = disconnecting;
			m_disconnect_future = ext::make_intrusive<ext::shared_state<void>>();
			m_connect_future->mark_uncancellable();

			do_disconnect_request(std::move(lk));
			return m_disconnect_future;

		default:
			on_bad_transaction();
		}
	}

	void abstract_connection_controller::notify_connected(unique_lock lk, bool success, std::exception_ptr eptr)
	{
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
			m_state = online;
			lk.unlock();

			set_result(connected, success, std::move(eptr));
			emit_signal(m_event_signal, connection_controller::connected);
			return;

			// should not happen
			//case Offline:
			//case Online:
		default:
			on_bad_transaction();
		}
	}

	void abstract_connection_controller::notify_disconnected(unique_lock lk)
	{
		assert(lk.owns_lock());
		auto connected = m_connect_future;
		auto disconnected = m_disconnect_future;

		switch (m_state)
		{
		case connecting:
			m_state = offline;
			lk.unlock();

			set_result(connected, false, nullptr);
			set_result(disconnected);

			emit_signal(m_event_signal, connection_controller::disconnected);
			emit_signal(m_event_signal, connection_controller::connection_error);
			return;

		case disconnecting:
			m_state = offline;
			lk.unlock();

			set_result(disconnected);
			set_result(connected, false, nullptr);
			emit_signal(m_event_signal, connection_controller::disconnected);
			return;

		case online:
			m_state = offline;
			lk.unlock();

			assert(connected->is_ready());
			set_result(disconnected);

			emit_signal(m_event_signal, connection_controller::disconnected);
			emit_signal(m_event_signal, connection_controller::connection_error);
			emit_signal(m_event_signal, connection_controller::connection_lost);
			return;

		// case Offline:
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
		unique_lock lk(m_mutex);
		return do_connect(lk);
	}

	ext::shared_future<void> abstract_connection_controller::disconnect()
	{
		unique_lock lk(m_mutex);
		return do_disconnect(lk);
	}

	abstract_connection_controller::abstract_connection_controller() = default;

	abstract_connection_controller::~abstract_connection_controller() noexcept
	{
		if (m_connect_future)    m_connect_future->release_promise();
		if (m_disconnect_future) m_disconnect_future->release_promise();
	}
}}
