#pragma once
#include <memory>
#include <ext/intrusive_ptr.hpp>
#include <ext/future.hpp>

#include <boost/signals2/slot.hpp>
#include <boost/signals2/connection.hpp>

namespace ext {
namespace net
{
	/// Abstract subscription controller, thread-safe.
	/// Represents subscription, working in some entity
	/// (possibly in separate thread or in completely separate process/host),
	/// Have methods for controlling subscription state and signals for notifications of state changes:
	/// * subscription paused
	/// * subscription resumed
	/// * subscription closed
	/// 
	/// pause/resume/close methods are non blocking as much as possible.
	/// Operation is allowed to complete in method immediately(if that's possible),
	/// and signals can be emitted from any thread, including thread method is called from.
	/// 
	/// NOTE:
	///   After successful transition to paused state - it's allowed to provide some left accumulated data.
	///   Implementation can provide more strict guarantees.
	///   After successful Closed - there are should no be any data.
	///
	///   Subscription always starts from opened state, and eventually is closed.
	///   It cannot come back to opened state. If it was closed - new one must be created.
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
	///    pausing      resume          pausing      delayed resume*
	///    pausing      evclosed        closed       emit closed signal
	///    pausing      evpaused        paused       emit paused signal
	///    pausing      evresumed       opened       emit resumed signal, unexpected resumed
	///    
	///    resuming     close           closing      place unsubscribe request
	///    resuming     pause           resuming     delayed pause
	///    resuming     resume          none
	///    resuming     evclosed        closed       emit closed signal
	///    resuming     evpaused        paused       emit paused signal, unexpected paused
	///    resuming     evresumed       opened       emit resumed signal
	///    
	///    In correctly implemented controller unexpected stuff should not happen.
	///    But it could be in another process/host, and notifications come though some connection(net, pipe etc)
	///    It would be good if we are able to work with them.
	///    Handle of such unexpected things are completely implementation defined,
	///    emitting signals and normal working is encouraged.
	///    
	///    delayed pause/resume - if we can't pause/resume immediately - there is pausing/resuming state.
	///    When in it we can't just start counterpart action until current is finished.
	///    In that case controller should remember that it should automatically pause/resume immediately after evresumed/evpaused happened.
	class subscription_controller : public ext::intrusive_atomic_counter<subscription_controller>
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

		enum delayed_state_type
		{
			normal,
			want_resume,
			want_pause,
		};

		typedef boost::signals2::slot<void(state_type ev)> event_slot;

	public:
		static const char * state_string(state_type state) noexcept;
		static const char * delayed_string(delayed_state_type state) noexcept;

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




	inline const char * subscription_controller::state_string(state_type state) noexcept
	{
		switch (state)
		{
			case state_type::opened:     return "online";
			case state_type::closed:     return "offline";
			case state_type::paused:     return "connecting";

			case state_type::closing:     return "closing";
			case state_type::pausing:     return "pausing";
			case state_type::resuming:    return "resuming";

			default: EXT_UNREACHABLE();
		}
	}

	inline const char * subscription_controller::delayed_string(delayed_state_type state) noexcept
	{
		switch (state)
		{
			case subscription_controller::delayed_state_type::normal:        return "normal";
			case subscription_controller::delayed_state_type::want_resume:   return "want_resume";
			case subscription_controller::delayed_state_type::want_pause:    return "want_pause";

			default: EXT_UNREACHABLE();
		}
	}

}}
