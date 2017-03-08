#pragma once
#include <memory>
#include <ext/future.hpp>
#include <boost/signals2/slot.hpp>
#include <boost/signals2/connection.hpp>

namespace ext {
namespace netlib
{
	/// Abstract subscription controller, thread-safe.
	/// Represents subscription, working in some entity
	/// (possibly in separate thread or in completely separate process/host), 
	/// Have methods for controlling subscription state and signals for notifications of state changes:	
	/// * subscription opened
	/// * subscription paused
	/// * subscription closed
	/// 
	/// connect/disconnect methods are non blocking as much as possible.
	/// Operation is allowed to complete in method immediately(if that's possible),
	/// and signals can be emitted from any thread, including thread method is called from.
	/// 
	/// NOTE:
	///   After successful transition to paused state - it's allowed to provide some left accamulated data.
	///   Implementation can provide more strict guarantees.
	///   After successful Closed - there are should no be any data.
	/// 
	/// State table:
	///       Start     Event           Next         Action
	///  +----------+--------------+--------------+------------
	///    opened       close           closing      place unsubscribe request
	///    opened       pause           pausing      place pause request
	///    opened       resume          opened       none
	///    opened       evclosed        closed       emit closed signal
	///    opened       evpaused        paused       emit paused signal, unexpected paused
	///    opened       evresumed       none         none, unexpected resumed
	///    
	///    closed       close           closed       none
	///    closed       pause           closed       none
	///    closed       resume          closed       none
	///    closed       evclosed        closed       none
	///    closed       evpaused        closed       none
	///    closed       evresumed       closed       none
	///    
	///    paused       close           closing      place unsubscribe request
	///    paused       pause           paused       none
	///    paused       resume          resuming     place resume request
	///    paused       evclosed        closed       emit closed signal
	///    paused       evpaused        none         none, unexpected paused
	///    paused       evresumed       opened       emit resumed signal, unexpected resumed
	/// 
	///    closing      close           none
	///    closing      pause           none
	///    closing      resume          none
	///    closing      evclosed        closed       emit closed signal
	///    closing      evpaused        none         none
	///    closing      evresumed       none         none
	///    
	///    pausing      close           closing      place unsubscribe request
	///    pausing      pause           none
	///    pausing      resume          BadRequest
	///    pausing      evclosed        closed       emit closed signal
	///    pausing      evpaused        paused       emit paused signal
	///    pausing      evresumed       opened       emit resumed signal, unexpected resumed
	///    
	///    resuming     close           closing      place unsubscribe request
	///    resuming     pause           BadRequest
	///    resuming     resume          none
	///    resuming     evclosed        closed       emit closed signal
	///    resuming     evpaused        paused       emit paused signal, unexpected paused
	///    resuming     evresumed       opened       emit resumed signal
	///    
	///    In correctly implemented controller unexpected stuff should not happed.
	///    But it could be in another process/host, and notifications come though some connection(net, pipe etc)
	///    It would good if we are able to work with them. 
	///    Handle of such unexpected things are completely implementation defined,
	///    emitting signals and normal working is encouraged.
	///    
	///    BadRequest - is logical error.
	///    Client should not issue Resume until subscription is paused
	///                            Pause until subscription is resumed
	///    Implementation should throw std::logic_error derived exception in such cases.
	class subscription_controller
	{
	public:
		enum state_type
		{
			// those can be returned from get_state and event_slot
			opened,     /// subscription is in normal working state
			resumed = opened, /// used in event signal, for simplification alias to opened
			
			closed,     /// subscription is closed, can't be resumed
			paused,     /// subscription is paused, can be resumed			

			// those can be returned only from get_state
			closing,    /// subscription is closing 
			pausing,    /// subscription is pausing
			resuming,   /// subscription is resuming
		};

		typedef boost::signals2::slot<void(state_type ev)> event_slot;

	public:
		/// current state of connection,
		/// actually it can be changed immediately after call.
		virtual state_type get_state() = 0;
		/// Makes close request.
		/// Returns future<void> - result of connection 
		virtual ext::shared_future<void> close() = 0;
		/// Makes pause request.
		/// Returns future<bool> - result of connection 
		/// @Throws std::logic_error, see class decription
		virtual ext::shared_future<bool> pause() = 0;
		/// Makes resume request.
		/// Returns future<bool> - result of connection 
		/// @Throws std::logic_error, see class decription
		virtual ext::shared_future<bool> resume() = 0;
		/// event signal, event is identified with state_type		
		virtual boost::signals2::connection on_event(const event_slot & slot) = 0;

		virtual ~subscription_controller() = default;
	};
}}
