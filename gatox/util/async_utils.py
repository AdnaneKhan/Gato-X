import asyncio
from concurrent.futures import ThreadPoolExecutor

executor = ThreadPoolExecutor()

def async_wrap(func, *args, **kwargs):
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        # We're already in a running event loop
        # Define a function to run the coroutine in a new event loop
        def run_coroutine_in_thread():
            # Create a new event loop for this thread
            new_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(new_loop)
            try:
                # Run the coroutine in this thread's event loop
                return new_loop.run_until_complete(func(*args, **kwargs))
            finally:
                # Clean up
                new_loop.close()

        # Run this function in the executor and wait for it to complete
        return executor.submit(run_coroutine_in_thread).result()
    else:
        return asyncio.run(func(*args, **kwargs))