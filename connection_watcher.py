#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
import threading
import logging

class ConnectionWatcher:
    def __init__(self, network_handler):
        self.network_handler = network_handler
        self.running = True

    def start_periodic_check(self, interval=300):
        def check():
            while self.running:
                try:
                    status = self.network_handler.check_all_connections()
                    logging.info(f"Connection status: {status}")
                except Exception as e:
                    logging.error(f"Connection watch error: {e}")
                time.sleep(interval)
        threading.Thread(target=check, daemon=True).start()

    def stop(self):
        self.running = False
