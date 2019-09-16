#pragma once
#include <memory>
#include <ext/future.hpp>
#include <boost/signals2/slot.hpp>
#include <boost/signals2/connection.hpp>

namespace ext {
namespace net
{
	/// Abstract connection controller, thread-safe.
	/// Represents connection, which is lives/works in separate thread or some other entity.
	/// Have methods for controlling state of connection and signals for notifications of state changes:
	///   * connection done
	///   * disconnection done
	///   * connection lost
	///   * connection error
	/// 
	/// connect/disconnect methods are non blocking as much as possible.
	/// Operation is allowed to complete in method immediately(if that's possible),
	/// and signals can be emitted from any thread, including thread method is called from.
	/// 
	/// State table:
	///     Start          Event               Next         Action
	///  +------------+------------------+-------------+------------
	///    offline         disconnect        offline         none
	///    offline         disconnected      offline         none
	///    offline         connect           connecting      place connect request
	///    offline         connected         BadTransactionRequest
	///    
	///    connecting      connect           connecting      none
	///    connecting      connected         online          emit connected signal
	///    connecting      disconnect        disconnecting   place disconnect request
	///    connecting      disconnected      offline         emit signals: disconnect, connection error
	///    
	///    online          connect           online          none
	///    online          connected         BadTransactionRequest
	///    online          disconnect        disconnecting   place disconnect request
	///    online          disconnected      offline         emit signals: disconnect, connection error, connection lost
	///    
	///    disconnecting   connect           disconnecting   delayed connect*
	///    disconnecting   connected         none            ignore, see below
	///    disconnecting   disconnect        disconnecting   none
	///    disconnecting   disconnected      offline         emit disconnect signal
	///    
	///    It can happen that connection was successful, but state machine was already transferred to disconnect state.
	///    State machine should ignore that conflict, and implementation should disconnect immediately after that.
	///    (disconnect request should not be lost)
	///    
	///    In correctly implemented controller BadTransactionRequest should not happen.
	///    Handle of such state is implementation-defined, but not ignoring.
	///    Throw exception, call std::terminate etc.
	///    
	///    delayed connect - if we can't disconnect immediately - there is disconnecting state.
	///    When in it we can't just start connecting until disconnect is finished.
	///    In that case controller should remember that it should automatically connect immediately after disconnect happened.
	class connection_controller
	{
	public:
		enum state_type
		{
			online,
			offline,
			connecting,
			disconnecting
		};

		enum event_type
		{
			connected,
			disconnected,
			connection_lost,
			connection_error,
		};

		enum delayed_state_type
		{
			normal,
			want_connect,
			// want_disconnect,
		};

		typedef boost::signals2::slot<void(event_type ev)> event_slot;

	public:
		static const char * state_string(state_type state) noexcept;
		static const char * delayed_string(delayed_state_type state) noexcept;

	public:
		/// current state of connection,
		/// actually it can be changed immediately after call.
		virtual state_type get_state() = 0;

		/// Make connect request.
		/// Returns future<bool> - result of connection
		/// @Throws std::logic_error see class decription
		virtual ext::shared_future<bool> connect() = 0;
		/// Makes disconnect request.
		/// Returns future<void> - result of disconnection
		virtual ext::shared_future<void> disconnect() = 0;
		/// event signal, event is identified with event_type
		virtual boost::signals2::connection on_event(const event_slot & slot) = 0;

		virtual ~connection_controller() = default;
	};




	inline const char * connection_controller::state_string(state_type state) noexcept
	{
		switch (state)
		{
			case state_type::online:         return "online";
			case state_type::offline:        return "offline";
			case state_type::connecting:     return "connecting";
			case state_type::disconnecting:  return "disconnecting";

			default: EXT_UNREACHABLE();
		}
	}

	inline const char * connection_controller::delayed_string(delayed_state_type state) noexcept
	{
		switch (state)
		{
			case delayed_state_type::normal:         return "normal";
			case delayed_state_type::want_connect:   return "want_connect";

			default: EXT_UNREACHABLE();
		}
	}

}}
