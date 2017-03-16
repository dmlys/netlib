#pragma once
#include <memory>
#include <boost/operators.hpp>
#include <ext/netlib/subscription_controller.hpp>

namespace ext {
namespace netlib
{
	/// Value handle wrapper for subscription_controller.
	/// Close transfers handle into detached state,
	/// may be it's not needed, but, it's looks like it does not conflicts with contracts,
	/// cause after close there is nothing to do with subscription by fact(see subscription_controller state table).
	class subscription_handle : boost::totally_ordered<subscription_handle>
	{
	public:
		typedef ext::intrusive_ptr<subscription_controller> subscription_ptr;
		typedef subscription_controller::event_slot event_slot;
		typedef subscription_controller::state_type state_type;

	private:
		subscription_ptr m_ptr;

	private:
		BOOST_NORETURN static void throw_closed_handle() { throw std::logic_error("subsciption_handle is closed"); }

	public:
		auto get() const noexcept                  { return m_ptr; }
		void assign(subscription_ptr ptr) noexcept { m_ptr = std::move(ptr); }
		bool empty() const                noexcept { return static_cast<bool>(m_ptr); }
		void reset()                      noexcept { m_ptr.reset(); }
		operator bool() const             noexcept { return not empty(); }

	public: // operators
		bool operator  <(const subscription_handle & other) const
		{
			return m_ptr < other.m_ptr;
		}

		bool operator ==(const subscription_handle & other) const
		{
			return m_ptr == other.m_ptr;
		}

	public: // interface
		state_type get_state()
		{			
			return m_ptr ? m_ptr->get_state() : subscription_controller::closed;
		}
		
		auto pause()
		{
			return m_ptr ? m_ptr->pause() : ext::make_ready_future(false);
		}

		auto resume()
		{
			return m_ptr ? m_ptr->resume() : ext::make_ready_future(false);
		}

		void close()
		{			
			if (m_ptr) m_ptr->close();
			m_ptr.reset();
		}

		auto on_event(const event_slot & slot)
		{
			return m_ptr ? m_ptr->on_event(slot) : boost::signals2::connection();
		}

	public:
		subscription_handle() = default;
		subscription_handle(subscription_ptr ptr) : m_ptr(std::move(ptr)) {}
	};
}}
