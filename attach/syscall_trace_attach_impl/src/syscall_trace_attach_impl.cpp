#include "spdlog/spdlog.h"
#include "syscall_trace_attach_private_data.hpp"
#include <atomic>
#include <cerrno>
#include <cstring>
#include <errno.h> // For ENOSYS and other error codes
#include <iterator>
#include <optional>
#include <atomic>
// Remove locale-dependent formatting
// #include <format>
#include <iostream>
#include <syscall_trace_attach_impl.hpp>
#include <thread>
#include <mutex>
#include <shared_mutex>
#include <locale.h> // For setlocale
#include <unordered_set>

#ifdef __linux__
#include <asm/unistd.h> // For architecture-specific syscall numbers
#include <sys/syscall.h> // For SYS_gettid
#include <locale.h> // For uselocale, newlocale
#endif

// FS register offset for storing the locale initialization flag
// Use a high offset to avoid conflicts with other TLS variables
#define FS_LOCALE_INIT_OFFSET 0x900

// Direct FS register access to check if locale is initialized for current
// thread
static inline bool is_locale_initialized()
{
#ifdef __x86_64__
	bool result;
	__asm__ volatile("movb %%fs:%c1, %0" // Read from
					     // FS:FS_LOCALE_INIT_OFFSET
			 : "=r"(result)
			 : "i"(FS_LOCALE_INIT_OFFSET)
			 : "memory");
	return result;
#else
	// Fallback for non-x86_64 platforms
	static thread_local bool tls_locale_initialized = false;
	return tls_locale_initialized;
#endif
}

// Direct FS register access to mark locale as initialized for current thread
static inline void mark_locale_initialized()
{
#ifdef __x86_64__
	bool value = true;
	__asm__ volatile("movb %0, %%fs:%c1" // Write to
					     // FS:FS_LOCALE_INIT_OFFSET
			 :
			 : "r"(value), "i"(FS_LOCALE_INIT_OFFSET)
			 : "memory");
#else
	// Fallback for non-x86_64 platforms
	static thread_local bool tls_locale_initialized = true;
#endif
}

// Initialize FS locale tracking storage with zeros
// This should be called very early
static inline void init_locale_tracking()
{
#ifdef __x86_64__
	bool value = false;
	__asm__ volatile("movb %0, %%fs:%c1" // Write to
					     // FS:FS_LOCALE_INIT_OFFSET
			 :
			 : "r"(value), "i"(FS_LOCALE_INIT_OFFSET)
			 : "memory");
#endif
}

// Per-thread locale initialization
// This sets the locale to C for the current thread only
static void init_thread_locale()
{
	// We need to use the thread-safe version of setlocale that only affects
	// the current thread. This is crucial for preventing conflicts between
	// threads
#ifdef __linux__
	uselocale(newlocale(LC_ALL_MASK, "C", (locale_t)0));
	// Mark locale as initialized using direct FS register access
	mark_locale_initialized();
#else
	// Fallback for platforms without thread-specific locale
	setlocale(LC_ALL, "C");
#endif
}

// Track threads that were recently created and should bypass all syscall
// interception until they are fully initialized
class NewThreadTracker {
    private:
	std::mutex mutex_;
	std::unordered_set<pid_t> new_threads_;
	std::atomic<int> tracking_counter_{ 0 };
	// Set to track threads that have had their locale initialized
	std::unordered_set<pid_t> locale_initialized_threads_;

    public:
	// Called when a thread creation syscall completes
	void add_new_thread(pid_t tid)
	{
		if (tid <= 0)
			return;

		std::lock_guard<std::mutex> lock(mutex_);
		new_threads_.insert(tid);
		tracking_counter_.fetch_add(1);
	}

	// Check if a thread is new and should bypass syscall interception
	bool is_new_thread(pid_t tid)
	{
		if (tracking_counter_.load(std::memory_order_relaxed) == 0)
			return false;

		std::lock_guard<std::mutex> lock(mutex_);
		return new_threads_.find(tid) != new_threads_.end();
	}

	// Remove a thread from the new thread list
	void remove_thread(pid_t tid)
	{
		if (tracking_counter_.load(std::memory_order_relaxed) == 0)
			return;

		std::lock_guard<std::mutex> lock(mutex_);
		if (new_threads_.erase(tid) > 0) {
			tracking_counter_.fetch_sub(1);
		}
	}

	// Check if we should initialize locale for this thread and do so if
	// needed
	void maybe_init_thread_locale(pid_t tid)
	{
		// First check using direct FS register access
		if (is_locale_initialized()) {
			return;
		}

		// Now check if we've recorded this thread as already
		// initialized
		{
			std::lock_guard<std::mutex> lock(mutex_);
			if (locale_initialized_threads_.find(tid) !=
			    locale_initialized_threads_.end()) {
				return;
			}

			// Mark this thread as having its locale initialized
			locale_initialized_threads_.insert(tid);
		}

		// Initialize the locale for this thread
		init_thread_locale();
	}
};

// Global new thread tracker
static NewThreadTracker new_thread_tracker;

// Critical syscall list - these are common during initialization
#ifdef __linux__
static const int critical_syscalls[] = {
	257, // openat
	3, // close
	0, // read
	8, // lseek
	5, // fstat
	4, // stat
	6, // lstat
	228, // clock_gettime
	231, // exit_group
	60, // exit
	12, // brk
	2, // open
	21, // access
	57, // fork
	58, // vfork
};
#endif

// Flag to disable all formatting and logging in critical paths
static std::atomic<bool> g_bypass_logging(false);

// Basic direct syscall implementation to avoid any libc dependencies
static long raw_syscall(long syscall_nr, long arg1 = 0, long arg2 = 0,
			long arg3 = 0, long arg4 = 0, long arg5 = 0,
			long arg6 = 0)
{
#ifdef __x86_64__
	long result;
	register long r10 __asm__("r10") = arg4;
	register long r8 __asm__("r8") = arg5;
	register long r9 __asm__("r9") = arg6;

	__asm__ volatile("syscall"
			 : "=a"(result)
			 : "a"(syscall_nr), "D"(arg1), "S"(arg2), "d"(arg3),
			   "r"(r10), "r"(r8), "r"(r9)
			 : "rcx", "r11", "memory");

	return result;
#else
#error "Architecture not supported for direct syscall"
#endif
}

namespace bpftime
{
namespace attach
{

// Safe logging helper that avoids locale-dependent functions
static void safe_log(const char *message)
{
	if (!g_bypass_logging.load()) {
		// Use direct write syscall to avoid any locale dependencies
		static const char prefix[] = "[SYSCALL TRACER] ";
		raw_syscall(1, STDERR_FILENO, (long)prefix,
			    sizeof(prefix) - 1); // write syscall
		raw_syscall(1, STDERR_FILENO, (long)message,
			    strlen(message)); // write syscall
		raw_syscall(1, STDERR_FILENO, (long)"\n", 1); // write syscall
	}
}

// 使用std::atomic<syscall_trace_attach_impl*>代替std::atomic<std::optional<syscall_trace_attach_impl
// *>>
std::atomic<syscall_trace_attach_impl *> global_syscall_trace_attach_impl{
	nullptr
};

// Thread-local t_info struct to prevent race conditions
typedef struct {
	bool *is_overrided;
	uint64_t *user_ret, *user_ret_ctx;
} t_info_t;

// Make t_info thread-local to prevent race conditions
// Use static to ensure it's initialized early and accessible
static thread_local t_info_t t_info = { nullptr, nullptr, nullptr };

// Function to safely access the t_info structure
// Avoids issues with TLS not being initialized yet
static t_info_t *get_t_info_safe()
{
	// Fallback for cases where TLS might not be initialized yet
	static bool fallback_is_overrided = false;
	static uint64_t fallback_user_ret = 0;
	static uint64_t fallback_user_ret_ctx = 0;

	// Check if t_info is properly initialized
	if (t_info.is_overrided == nullptr) {
		// Not initialized yet, use fallback
		t_info.is_overrided = &fallback_is_overrided;
		t_info.user_ret = &fallback_user_ret;
		t_info.user_ret_ctx = &fallback_user_ret_ctx;
	}

	return &t_info;
}

static void internal_callback(uint64_t ctx, uint64_t v)
{
	auto info = get_t_info_safe();
	*(info->user_ret) = v;
	*(info->user_ret_ctx) = ctx;
	*(info->is_overrided) = true;
}

// A thread-safe set to track threads currently processing a syscall
// This avoids TLS conflicts by using thread IDs directly
class ThreadTracker {
    private:
	std::mutex mutex_;
	std::unordered_set<pid_t> active_threads_;

    public:
	// Get current thread ID in a platform-independent way
	static pid_t get_current_thread_id()
	{
#ifdef __linux__
		// Use our raw syscall implementation to avoid libc
		return raw_syscall(SYS_gettid);
#else
		// Fallback for non-Linux platforms
		static std::atomic<pid_t> fake_tid{ 0 };
		thread_local pid_t thread_id = fake_tid.fetch_add(1) + 1;
		return thread_id;
#endif
	}

	bool is_thread_active()
	{
		pid_t tid = get_current_thread_id();
		std::lock_guard<std::mutex> lock(mutex_);
		return active_threads_.find(tid) != active_threads_.end();
	}

	void mark_thread_active()
	{
		pid_t tid = get_current_thread_id();
		std::lock_guard<std::mutex> lock(mutex_);
		active_threads_.insert(tid);
	}

	void mark_thread_inactive()
	{
		pid_t tid = get_current_thread_id();
		std::lock_guard<std::mutex> lock(mutex_);
		active_threads_.erase(tid);
	}
};

// Global thread tracker instance
static ThreadTracker thread_tracker;

// Additional safety check - use atomic counter for excessive recursion
// detection
static std::atomic<int> recursion_detection{ 0 };

// Helper function to check if syscall is critical
static bool is_critical_syscall(int64_t sys_nr)
{
#ifdef __linux__
	for (auto critical_nr : critical_syscalls) {
		if (sys_nr == critical_nr) {
			return true;
		}
	}
#endif
	return false;
}

// Check if syscall is a thread creation syscall
static bool is_thread_creation_syscall(int64_t sys_nr)
{
#ifdef __linux__
	return sys_nr == SYS_clone || sys_nr == 435 /*SYS_clone3*/ ||
	       sys_nr == SYS_fork || sys_nr == SYS_vfork;
#else
	return false;
#endif
}

int64_t syscall_trace_attach_impl::dispatch_syscall(int64_t sys_nr,
						    int64_t arg1, int64_t arg2,
						    int64_t arg3, int64_t arg4,
						    int64_t arg5, int64_t arg6)
{

// Exit syscall may cause bugs since it's not return to userspace
#ifdef __linux__
	if (sys_nr == __NR_exit_group || sys_nr == __NR_exit ||
	    sys_nr == __NR_openat || sys_nr == __NR_sched_getaffinity ||
	    sys_nr == __NR_read || sys_nr == __NR_close)
		return orig_syscall(sys_nr, arg1, arg2, arg3, arg4, arg5, arg6);

#endif
	// Get the current thread ID early
	pid_t tid = ThreadTracker::get_current_thread_id();

	// Try to initialize locale for this thread if needed
	new_thread_tracker.maybe_init_thread_locale(tid);

	// If this is a new thread in initialization phase, bypass all
	// interception
	if (new_thread_tracker.is_new_thread(tid) || sys_nr < 0) {
		// A negative syscall number is often seen during thread
		// initialization Bypass all interception for new threads or
		// negative syscall numbers
		if (sys_nr < 0) {
			// After seeing a negative syscall, this thread is
			// considered initialized
			new_thread_tracker.remove_thread(tid);
		}
		return orig_syscall(sys_nr, arg1, arg2, arg3, arg4, arg5, arg6);
	}

	// Immediately bypass for critical syscalls to avoid locale issues
	if (is_critical_syscall(sys_nr)) {
		// Execute original syscall directly
		int64_t ret = orig_syscall(sys_nr, arg1, arg2, arg3, arg4, arg5,
					   arg6);

		// Check if this was a thread creation syscall and track the new
		// thread
		if (is_thread_creation_syscall(sys_nr) && ret > 0) {
			// A successful thread creation returns the new thread
			// ID
			new_thread_tracker.add_new_thread(ret);
		}

		return ret;
	}

	// Check if this thread is already dispatching (to prevent recursion)
	if (thread_tracker.is_thread_active() ||
	    recursion_detection.load() > 10) {
		// Already dispatching or excessive recursion detected
		return orig_syscall(sys_nr, arg1, arg2, arg3, arg4, arg5, arg6);
	}

	// Mark this thread as active
	thread_tracker.mark_thread_active();
	int counter_val = recursion_detection.fetch_add(1);

	// RAII guard to reset flags on function exit
	struct RecursionGuard {
		RecursionGuard()
		{
		}
		~RecursionGuard()
		{
			thread_tracker.mark_thread_inactive();
			recursion_detection.fetch_sub(1);
		}
	} guard;

	// Only log if not in a potential TLS situation to avoid logging
	// recursion
	if (counter_val < 2 && !g_bypass_logging.load()) {
		// Use safer logging methods without std::format
		char buf[256];
		snprintf(buf, sizeof(buf), "Syscall dispatch: %ld", sys_nr);
		safe_log(buf);
	}

	// Indicate whether the return value is overridden
	bool is_overrided = false;
	uint64_t user_ret = 0;
	uint64_t user_ret_ctx = 0;

	// Use our safe TLS accessor to avoid TLS initialization issues
	auto info = get_t_info_safe();
	info->is_overrided = &is_overrided;
	info->user_ret = &user_ret;
	info->user_ret_ctx = &user_ret_ctx;

	// Set the callback for overriding return values
	curr_thread_override_return_callback = internal_callback;

	// Acquire shared lock for reading callbacks
	{
		std::shared_lock<std::shared_mutex> lock(callbacks_mutex);
		// Bounds checking for sys_nr to prevent invalid array access
		const size_t sys_callbacks_size =
			std::size(sys_enter_callbacks);
		const bool sys_nr_valid =
			sys_nr >= 0 &&
			sys_nr < static_cast<int64_t>(sys_callbacks_size);

		if ((sys_nr_valid && !sys_enter_callbacks[sys_nr].empty()) ||
		    !global_enter_callbacks.empty()) {
			trace_event_raw_sys_enter ctx;
			memset(&ctx, 0, sizeof(ctx));
			ctx.id = sys_nr;
			ctx.args[0] = arg1;
			ctx.args[1] = arg2;
			ctx.args[2] = arg3;
			ctx.args[3] = arg4;
			ctx.args[4] = arg5;
			ctx.args[5] = arg6;

			// Only access sys_enter_callbacks if sys_nr is valid
			if (sys_nr_valid) {
				for (auto prog : sys_enter_callbacks[sys_nr]) {
					auto ctx_copy = ctx;
					uint64_t ret;
					int err = prog->cb(&ctx_copy,
							   sizeof(ctx_copy),
							   &ret);
					// Skip debug logging
				}
			}
			for (auto prog : global_enter_callbacks) {
				auto ctx_copy = ctx;
				uint64_t ret;
				int err = prog->cb(&ctx_copy, sizeof(ctx_copy),
						   &ret);
				// Skip debug logging
			}
		}
	}

	// Reset TLS info and callback
	curr_thread_override_return_callback.reset();
	if (is_overrided) {
		return user_ret;
	}

	// Use our safe TLS accessor again for exit callbacks
	info = get_t_info_safe();
	info->is_overrided = &is_overrided;
	info->user_ret = &user_ret;
	info->user_ret_ctx = &user_ret_ctx;
	curr_thread_override_return_callback = internal_callback;

	// Skip debug logging
	int64_t ret = orig_syscall(sys_nr, arg1, arg2, arg3, arg4, arg5, arg6);

	// Acquire shared lock for reading callbacks
	{
		std::shared_lock<std::shared_mutex> lock(callbacks_mutex);
		// Bounds checking for sys_nr to prevent invalid array access
		const size_t sys_callbacks_size = std::size(sys_exit_callbacks);
		const bool sys_nr_valid =
			sys_nr >= 0 &&
			sys_nr < static_cast<int64_t>(sys_callbacks_size);

		if ((sys_nr_valid && !sys_exit_callbacks[sys_nr].empty()) ||
		    !global_exit_callbacks.empty()) {
			trace_event_raw_sys_exit ctx;
			memset(&ctx, 0, sizeof(ctx));
			ctx.id = sys_nr;
			ctx.ret = ret;

			// Only access sys_exit_callbacks if sys_nr is valid
			if (sys_nr_valid) {
				for (auto prog : sys_exit_callbacks[sys_nr]) {
					auto ctx_copy = ctx;
					uint64_t ret;
					int err = prog->cb(&ctx_copy,
							   sizeof(ctx_copy),
							   &ret);
					// Skip debug logging
				}
			}

			for (const auto prog : global_exit_callbacks) {
				auto ctx_copy = ctx;
				uint64_t ret;
				int err = prog->cb(&ctx_copy, sizeof(ctx_copy),
						   &ret);
				// Skip debug logging
			}
		}
	}

	curr_thread_override_return_callback.reset();
	if (is_overrided) {
		return user_ret;
	}
	return ret;
}

int syscall_trace_attach_impl::detach_by_id(int id)
{
	SPDLOG_DEBUG("Detaching syscall trace attach entry {}", id);
	// Acquire exclusive lock for modifying callbacks and attach_entries
	std::unique_lock<std::shared_mutex> lock(callbacks_mutex);

	if (auto itr = attach_entries.find(id); itr != attach_entries.end()) {
		const auto &ent = itr->second;
		if (ent->is_enter && ent->sys_nr == -1) {
			global_enter_callbacks.erase(ent.get());
		} else if (!ent->is_enter && ent->sys_nr == -1) {
			global_exit_callbacks.erase(ent.get());
		} else if (ent->is_enter) {
			sys_enter_callbacks[ent->sys_nr].erase(ent.get());
		} else if (!ent->is_enter) {
			sys_exit_callbacks[ent->sys_nr].erase(ent.get());
		} else {
			SPDLOG_ERROR("Unreachable branch reached!");
			return -EINVAL;
		}
		attach_entries.erase(itr);
		return 0;
	} else {
		SPDLOG_ERROR("Invalid attach id {}", id);
		return -ENOENT;
	}
}
int syscall_trace_attach_impl::create_attach_with_ebpf_callback(
	ebpf_run_callback &&cb, const attach_private_data &private_data,
	int attach_type)
{
	if (attach_type != ATTACH_SYSCALL_TRACE) {
		SPDLOG_ERROR(
			"Unsupported attach type {} by syscall trace attach impl",
			attach_type);
		return -ENOTSUP;
	}
	try {
		auto &priv_data =
			dynamic_cast<const syscall_trace_attach_private_data &>(
				private_data);
		if (priv_data.sys_nr >= (int)std::size(sys_enter_callbacks) ||
		    priv_data.sys_nr < -1) {
			SPDLOG_ERROR("Invalid sys nr {}", priv_data.sys_nr);
			return -EINVAL;
		}
		auto ent_ptr = std::make_unique<syscall_trace_attach_entry>(
			syscall_trace_attach_entry{
				.cb = cb,
				.sys_nr = priv_data.sys_nr,
				.is_enter = priv_data.is_enter });
		auto raw_ptr = ent_ptr.get();
		int id = allocate_id();

		// Acquire exclusive lock for modifying callbacks and
		// attach_entries
		std::unique_lock<std::shared_mutex> lock(callbacks_mutex);

		attach_entries[id] = std::move(ent_ptr);
		if (priv_data.is_enter) {
			if (priv_data.sys_nr == -1)
				global_enter_callbacks.insert(raw_ptr);
			else
				sys_enter_callbacks[priv_data.sys_nr].insert(
					raw_ptr);
		} else {
			if (priv_data.sys_nr == -1)
				global_exit_callbacks.insert(raw_ptr);
			else
				sys_exit_callbacks[priv_data.sys_nr].insert(
					raw_ptr);
		}
		return id;
	} catch (const std::bad_cast &ex) {
		SPDLOG_ERROR(
			"Syscall trace attach manager expected a private data of type syscall_trace_attach_private_data: {}",
			ex.what());
		return -EINVAL;
	}
}

extern "C" int64_t _bpftime__syscall_dispatcher(int64_t sys_nr, int64_t arg1,
						int64_t arg2, int64_t arg3,
						int64_t arg4, int64_t arg5,
						int64_t arg6)
{
	// For newly created threads, initialize FS register locale tracking
	// This is a no-op if it's already been initialized
	if (!is_locale_initialized()) {
		init_locale_tracking();
	}

	// Get the current thread ID early
	pid_t tid = ThreadTracker::get_current_thread_id();

	// Try to initialize locale for this thread if needed
	new_thread_tracker.maybe_init_thread_locale(tid);

	// If this is a new thread in initialization phase, bypass all
	// interception
	if (new_thread_tracker.is_new_thread(tid) || sys_nr < 0) {
		// Get direct access to original syscall function
		syscall_trace_attach_impl *impl =
			global_syscall_trace_attach_impl.load();
		if (impl) {
			auto orig_func = impl->get_original_syscall_function();
			if (orig_func) {
				// Cleanup thread tracking if needed
				if (sys_nr < 0) {
					new_thread_tracker.remove_thread(tid);
				}
				return orig_func(sys_nr, arg1, arg2, arg3, arg4,
						 arg5, arg6);
			}
		}
		return -ENOSYS;
	}

	// Immediately bypass critical syscalls
	if (is_critical_syscall(sys_nr)) {
		// Set locale bypass flag during critical syscalls
		g_bypass_logging.store(true);

		// Get direct access to original syscall function
		syscall_trace_attach_impl *impl =
			global_syscall_trace_attach_impl.load();
		if (impl) {
			auto orig_func = impl->get_original_syscall_function();
			if (orig_func) {
				int64_t result =
					orig_func(sys_nr, arg1, arg2, arg3,
						  arg4, arg5, arg6);

				// Check if this was a thread creation syscall
				if (is_thread_creation_syscall(sys_nr) &&
				    result > 0) {
					// Track the new thread to bypass
					// interception during its
					// initialization
					new_thread_tracker.add_new_thread(
						result);
				}

				g_bypass_logging.store(false);
				return result;
			}
		}

		g_bypass_logging.store(false);
		return -ENOSYS;
	}

	// Check if this thread is already dispatching (to prevent recursion)
	if (thread_tracker.is_thread_active()) {
		// If we detect recursion, bypass to the original syscall
		// handler if possible
		syscall_trace_attach_impl *impl =
			global_syscall_trace_attach_impl.load();
		if (impl) {
			auto orig_func = impl->get_original_syscall_function();
			if (orig_func) {
				return orig_func(sys_nr, arg1, arg2, arg3, arg4,
						 arg5, arg6);
			}
		}
		// Fallback if we can't get original handler
		return -ENOSYS;
	}

	// Set the recursion guard
	struct DispatcherGuard {
		DispatcherGuard()
		{
			thread_tracker.mark_thread_active();
		}
		~DispatcherGuard()
		{
			thread_tracker.mark_thread_inactive();
		}
	} guard;

	// Only log if not in a TLS-related syscall to avoid recursive logging
	if (!(sys_nr == 257 || sys_nr == 3 || sys_nr == 0 || sys_nr == 9 ||
	      sys_nr == 10 || sys_nr == 11 || sys_nr == 8)) {
		SPDLOG_DEBUG(
			"Call syscall dispatcher: {} {}, {}, {}, {}, {}, {}",
			sys_nr, arg1, arg2, arg3, arg4, arg5, arg6);
	}

	// 获取global_syscall_trace_attach_impl的值并检查它是否有值
	syscall_trace_attach_impl *impl =
		global_syscall_trace_attach_impl.load();
	if (impl == nullptr) {
		SPDLOG_ERROR(
			"global_syscall_trace_attach_impl has no value, cannot dispatch syscall");
		return -1; // 返回错误
	}
	return impl->dispatch_syscall(sys_nr, arg1, arg2, arg3, arg4, arg5,
				      arg6);
}

extern "C" void
_bpftime__setup_syscall_hooker_callback(syscall_hooker_func_t *hooker)
{
	//	assert(global_syscall_trace_attach_impl.load().has_value());
	auto impl = global_syscall_trace_attach_impl.load();

	// Add mutex to protect the setup process
	static std::mutex setup_mutex;
	std::lock_guard<std::mutex> lock(setup_mutex);

	// 防止递归调用：检查当前hooker是否已经指向我们的分发器
	if (*hooker == _bpftime__syscall_dispatcher) {
		SPDLOG_WARN(
			"Syscall hooker already set to _bpftime__syscall_dispatcher, skipping to avoid recursive calls");
		return;
	}

	impl->set_original_syscall_function(*hooker);
	SPDLOG_DEBUG(
		"Saved original syscall hooker (original syscall function): {:x}",
		(uintptr_t)*hooker);
	*hooker = _bpftime__syscall_dispatcher;
	SPDLOG_DEBUG("Set syscall hooker to {:x}", (uintptr_t)*hooker);
}

} // namespace attach
} // namespace bpftime
