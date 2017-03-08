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
		typedef std::weak_ptr<subscription_controller> weak_ptr;
		typedef std::shared_ptr<subscription_controller> shared_ptr;
		typedef subscription_controller::event_slot event_slot;
		typedef subscription_controller::state_type state_type;

	private:
		weak_ptr m_handle;

	public:
		weak_ptr get() const         noexcept  { return m_handle; }
		shared_ptr lock()            noexcept  { return m_handle.lock(); }
		void assign(weak_ptr handle) noexcept  { m_handle = std::move(handle); }
		bool empty() const           noexcept  { return m_handle.expired(); }
		void reset()                 noexcept  { m_handle.reset(); }
		operator bool() const        noexcept  { return not empty(); }

	public: // operators
		bool operator  <(const subscription_handle & other) const
		{
			return m_handle.owner_before(other.m_handle);
		}

		bool operator ==(const subscription_handle & other) const
		{
			return not m_handle.owner_before(other.m_handle) && not other.m_handle.owner_before(m_handle);
		}

	public: // interface
		state_type get_state()
		{
			auto ptr = m_handle.lock();
			return ptr ? ptr->get_state() : subscription_controller::closed;
		}
		
		void pause()
		{
			auto ptr = m_handle.lock();
			if (ptr) ptr->pause();
		}

		void resume()
		{
			auto ptr = m_handle.lock();
			if (ptr) ptr->resume();
		}

		void close()
		{
			auto ptr = m_handle.lock();
			if (ptr) ptr->close();
			m_handle.reset();
		}

		void on_event(const event_slot & slot)
		{
			auto ptr = m_handle.lock();
			if (ptr) ptr->on_event(slot);
		}

	public:
		subscription_handle() = default;
		subscription_handle(std::weak_ptr<subscription_controller> handle) : m_handle(std::move(handle)) {}

		subscription_handle(const subscription_handle &) = default;
		subscription_handle & operator =(const subscription_handle &) = default;

		subscription_handle(subscription_handle && handle) noexcept
			: m_handle(std::move(handle.m_handle)) {}

		subscription_handle & operator =(subscription_handle && handle) noexcept
		{ m_handle = std::move(handle.m_handle); return *this; }

		friend void swap(subscription_handle & h1, subscription_handle & h2) noexcept
		{ return h1.m_handle.swap(h2.m_handle); }
	};
}}
