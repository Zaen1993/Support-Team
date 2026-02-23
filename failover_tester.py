#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
import threading
import logging

class FailoverTester:
    def __init__(self, conn_mgr):
        self.conn_mgr = conn_mgr
        self.running = True

    def start_periodic_check(self, interval=300):
        def check():
            while self.running:
                try:
                    status = self.conn_mgr.check_all_connections()
                    logging.info(f"Connection status: {status}")
                except Exception as e:
                    logging.error(f"Failover check error: {e}")
                time.sleep(interval)
        threading.Thread(target=check, daemon=True).start()

    def stop(self):
        self.running = False
