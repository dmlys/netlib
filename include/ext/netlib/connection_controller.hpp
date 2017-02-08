#pragma once
#include <memory>
#include <ext/future.hpp>
#include <boost/signals2/slot.hpp>
#include <boost/signals2/connection.hpp>

namespace ext {
namespace netlib
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
	///    disconnecting   connect           BadConnectRequest
	///    disconnecting   connected         none            ignore, see below
	///    disconnecting   disconnect        disconnecting   none
	///    disconnecting   disconnected      offline         emit disconnect signal
	///    
	///    It can happed that connection was successful, but state machine was already transferred to disconnect state.
	///    State machine should ignore that conflict, and implementation should disconnect immediately after that.
	///    (disconnect request should not be lost)
	///    
	///    In correctly implemented controller BadTransactionRequest should not happed.
	///    Handle of such state is implementation-defined way, but not ignore.
	///    Throw exception, call std::terminate etc.
	///    
	///    BadConnectRequest - is logical error.
	///    Client should not issue connect call until connection is before disconnected.
	///    Implementation should throw std::logic_error derived exception in such cases.
	///    TODO: can/should be this reworked, like scheduling connect call?
	class connection_controller
	{
	public:
		typedef boost::signals2::slot<void()> connected_slot;
		typedef boost::signals2::slot<void()> disconnected_slot;
		typedef boost::signals2::slot<void()> connection_lost_slot;
		typedef boost::signals2::slot<void()> connection_error_slot;

		enum state_type
		{
			online,
			offline,
			connecting,
			disconnecting
		};

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

		virtual boost::signals2::connection on_connected(const connected_slot & slot) = 0;
		virtual boost::signals2::connection on_disconnected(const disconnected_slot & slot) = 0;
		virtual boost::signals2::connection on_connection_lost(const connection_lost_slot & slot) = 0;
		virtual boost::signals2::connection on_connection_error(const connection_error_slot & slot) = 0;

		virtual ~connection_controller() = default;
	};
}}
