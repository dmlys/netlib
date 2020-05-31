#pragma once
#include <fmt/format.h>
#include <ext/library_logger/logger.hpp>
#include <ext/library_logger/logging_macros.hpp>

#define LOG_FATAL(...) EXTLL_FATAL_FMT(m_logger, __VA_ARGS__)
#define LOG_ERROR(...) EXTLL_ERROR_FMT(m_logger, __VA_ARGS__)
#define LOG_WARN(...) EXTLL_WARN_FMT(m_logger, __VA_ARGS__)
#define LOG_INFO(...) EXTLL_INFO_FMT(m_logger, __VA_ARGS__)
#define LOG_DEBUG(...) EXTLL_DEBUG_FMT(m_logger, __VA_ARGS__)
#define LOG_TRACE(...) EXTLL_TRACE_FMT(m_logger, __VA_ARGS__)

//#define LOG_FATAL(f, ...) EXTLL_FATAL_STR(m_logger, fmt::format("http_server {}, " f, fmt::ptr(this), ##__VA_ARGS__))
//#define LOG_ERROR(f, ...) EXTLL_ERROR_STR(m_logger, fmt::format("http_server {}, " f, fmt::ptr(this), ##__VA_ARGS__))
//#define LOG_WARN(f, ...) EXTLL_WARN_STR(m_logger, fmt::format("http_server {}, " f, fmt::ptr(this), ##__VA_ARGS__))
//#define LOG_INFO(f, ...) EXTLL_INFO_STR(m_logger, fmt::format("http_server {}, " f, fmt::ptr(this), ##__VA_ARGS__))
//#define LOG_DEBUG(f, ...) EXTLL_DEBUG_STR(m_logger, fmt::format("http_server {}, " f, fmt::ptr(this), ##__VA_ARGS__))
//#define LOG_TRACE(f, ...) EXTLL_TRACE_STR(m_logger, fmt::format("http_server {}, " f, fmt::ptr(this), ##__VA_ARGS__))

#define SOCK_LOG_FATAL(f, ...) EXTLL_FATAL_STR(m_logger, fmt::format("sock={}, " f, sock.handle(), ##__VA_ARGS__))
#define SOCK_LOG_ERROR(f, ...) EXTLL_ERROR_STR(m_logger, fmt::format("sock={}, " f, sock.handle(), ##__VA_ARGS__))
#define SOCK_LOG_WARN(f, ...) EXTLL_WARN_STR(m_logger, fmt::format("sock={}, " f, sock.handle(), ##__VA_ARGS__))
#define SOCK_LOG_INFO(f, ...) EXTLL_INFO_STR(m_logger, fmt::format("sock={}, " f, sock.handle(), ##__VA_ARGS__))
#define SOCK_LOG_DEBUG(f, ...) EXTLL_DEBUG_STR(m_logger, fmt::format("sock={}, " f, sock.handle(), ##__VA_ARGS__))
#define SOCK_LOG_TRACE(f, ...) EXTLL_TRACE_STR(m_logger, fmt::format("sock={}, " f, sock.handle(), ##__VA_ARGS__))
