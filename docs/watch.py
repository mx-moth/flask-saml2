#!/usr/bin/env python3
"""
Watch and rebuild the docs when changes are made.
"""
import http.server
import itertools
import os
import pathlib
import subprocess
import sys
import threading
import time

import inotify.adapters
import inotify.constants

HERE = pathlib.Path(__file__).absolute().parent


def drop_while_not_none(gen):
    for x in itertools.takewhile(lambda x: x is not None, gen):
        pass


def sensible_dir_watch(
    directory: pathlib.Path,
    sleep: float = 0.5,
    **kwargs,
):
    i = inotify.adapters.InotifyTree(directory.as_posix(), **kwargs)
    gen = i.event_gen()

    for event in gen:
        # inotify will yield a None every second if nothing else happens. Just
        # wait for a real event if that happens.
        if event is None:
            continue

        # Consume any extra events that just happened, waiting for another None
        # indicating that nothing has happened for a while. Sometimes saving
        # a file in e.g. vim causes multiple inotify events to happen.
        drop_while_not_none(gen)

        # Let the caller do their thing
        yield

        # Wait for a bit, so inotify events from the build process can catch up
        time.sleep(sleep)

        # Consume any extra events that just happened. Sometimes the build
        # process generates some extra events.
        drop_while_not_none(gen)


build_lock = threading.Lock()


def compile_docs():
    subprocess.run(["make", "html"], check=True, cwd=HERE)


def watch_dir(directory, mask):
    for _ in sensible_dir_watch(directory, mask=mask):
        if build_lock.acquire(blocking=False):
            try:
                compile_docs()
            finally:
                build_lock.release()


def serve_dir(directory, port):
    os.chdir(directory)
    http.server.test(http.server.SimpleHTTPRequestHandler, port=port)


def main():
    compile_docs()

    # Don't listen to all events, such as accessing and opening files, only
    # those that modify the source files
    mask = (
        inotify.constants.IN_MODIFY |
        inotify.constants.IN_CLOSE_WRITE |
        inotify.constants.IN_MOVED_FROM |
        inotify.constants.IN_MOVED_TO |
        inotify.constants.IN_CREATE |
        inotify.constants.IN_DELETE |
        inotify.constants.IN_DELETE_SELF |
        inotify.constants.IN_MOVE_SELF |
        0
    )

    dirs = [
        HERE / 'source',
        HERE.parent / 'flask_saml2'
    ]

    threads = []

    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    server = threading.Thread(target=serve_dir, args=(HERE / 'build' / 'html', port))
    server.start()

    threads.append(server)

    for directory in dirs:
        thread = threading.Thread(target=watch_dir, args=(directory, mask))
        thread.start()
        threads.append(thread)

    try:
        all(thread.join() for thread in threads)
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == '__main__':
    main()
