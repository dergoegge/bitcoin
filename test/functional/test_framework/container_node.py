#!/usr/bin/env python3
# Copyright (c) 2024-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Class for bitcoind node running in a container (for Antithesis testing)"""

import logging
import os
import subprocess
import time
from pathlib import Path

from .authproxy import JSONRPCException
from .test_node import TestNode, FailedToStartError, BITCOIND_PROC_WAIT_TIMEOUT
from .util import (
    get_auth_cookie,
    get_rpc_proxy,
)


class ContainerNode(TestNode):
    """A TestNode subclass for bitcoind running in a pre-existing container.

    This class is designed for Antithesis integration where:
    - Containers are pre-provisioned via docker-compose
    - bitcoind runs inside containers, controlled via docker exec
    - Service discovery uses DNS names (e.g., node0, node1)
    - Data directories are on shared volumes accessible to the test harness

    Key differences from TestNode:
    - No subprocess.Popen - bitcoind runs inside container
    - Process control via docker exec commands
    - RPC connection to container DNS name instead of 127.0.0.1
    - P2P connections use container DNS names
    """

    def __init__(self, i, datadir_path, *,
                 container_name,
                 rpc_host,
                 p2p_host,
                 rpc_port,
                 p2p_port,
                 chain,
                 timewait,
                 timeout_factor,
                 coverage_dir,
                 cwd,
                 extra_conf=None,
                 extra_args=None,
                 v2transport=False,
                 uses_wallet=False,
                 container_runtime="docker"):
        """
        Args:
            container_name: Docker/Podman container name (e.g., "node0")
            rpc_host: Hostname for RPC connections (usually same as container_name)
            p2p_host: Hostname for P2P connections (usually same as container_name)
            rpc_port: RPC port inside container
            p2p_port: P2P port inside container
            container_runtime: "docker" or "podman"
        """
        self.index = i
        self.p2p_conn_index = 1
        self.datadir_path = Path(datadir_path)
        self.bitcoinconf = self.datadir_path / "bitcoin.conf"
        self.stdout_dir = self.datadir_path / "stdout"
        self.stderr_dir = self.datadir_path / "stderr"
        self.chain = chain
        self.rpc_timeout = timewait
        self.timeout_factor = timeout_factor
        self.coverage_dir = coverage_dir
        self.cwd = cwd

        # Container-specific attributes
        self.container_name = container_name
        self.container_runtime = container_runtime
        self.rpc_host = rpc_host
        self.p2p_host = p2p_host
        self._rpc_port = rpc_port
        self._p2p_port = p2p_port

        # Store extra args for restarts
        self.extra_args = extra_args if extra_args is not None else []
        self.extra_conf = extra_conf

        # V2 transport settings
        self.default_to_v2 = v2transport
        self.use_v2transport = v2transport

        # State
        self.running = False
        self.process = None  # Not used in container mode, but kept for compatibility
        self.rpc_connected = False
        self._rpc = None
        self.reuse_http_connections = True
        self.url = None
        self.log = logging.getLogger(f'TestFramework.node{i}')

        self.p2ps = []
        self.mocktime = None

        # These are not used in container mode but kept for compatibility
        self.use_cli = False
        self.start_perf = False
        self.perf_subprocesses = {}
        self.version = None
        self.binaries = None
        self.has_explicit_bind = False
        self.ipc_tmp_dir = None  # Not used in container mode

    def _exec_in_container(self, cmd, check=True, capture_output=True, timeout=None):
        """Execute a command inside the container."""
        full_cmd = [self.container_runtime, "exec", self.container_name] + cmd
        self.log.debug(f"Executing in container: {' '.join(full_cmd)}")
        return subprocess.run(
            full_cmd,
            check=check,
            capture_output=capture_output,
            text=True,
            timeout=timeout
        )

    def _exec_in_container_detached(self, cmd):
        """Execute a command inside the container in detached mode."""
        full_cmd = [self.container_runtime, "exec", "-d", self.container_name] + cmd
        self.log.debug(f"Executing in container (detached): {' '.join(full_cmd)}")
        return subprocess.run(full_cmd, check=True, capture_output=True, text=True)

    def start(self, extra_args=None, *, cwd=None, stdout=None, stderr=None, env=None, **kwargs):
        """Start bitcoind inside the container via docker exec."""
        if extra_args is None:
            extra_args = self.extra_args

        # Build bitcoind command
        bitcoind_args = [
            "bitcoind",
            f"-datadir={self.datadir_path}",
            "-logtimemicros",
            "-debug",
            "-debugexclude=libevent",
            "-debugexclude=leveldb",
            "-debugexclude=rand",
            f"-uacomment=testnode{self.index}",
            "-logthreadnames",
            "-logsourcelocations",
            "-loglevel=trace",
        ]

        # Add v2transport setting
        if self.default_to_v2:
            bitcoind_args.append("-v2transport=1")
        else:
            bitcoind_args.append("-v2transport=0")

        # Update use_v2transport based on extra_args
        self.use_v2transport = "-v2transport=1" in extra_args or (
            self.default_to_v2 and "-v2transport=0" not in extra_args
        )

        # Add extra args
        bitcoind_args.extend(extra_args)

        try:
            self._exec_in_container_detached(bitcoind_args)
            self.running = True
            self.log.debug(f"bitcoind started in container {self.container_name}")
        except subprocess.CalledProcessError as e:
            raise FailedToStartError(
                f"Failed to start bitcoind in container {self.container_name}: {e.stderr}"
            )

    def wait_for_rpc_connection(self, *, wait_for_import=True):
        """Wait for RPC connection to become available."""
        poll_per_s = 4
        for _ in range(poll_per_s * self.rpc_timeout):
            # Check if bitcoind process is still running
            if not self._is_bitcoind_running():
                raise FailedToStartError(
                    f"bitcoind in container {self.container_name} exited unexpectedly"
                )

            try:
                rpc = get_rpc_proxy(
                    self._build_rpc_url(),
                    self.index,
                    timeout=self.rpc_timeout // 2,
                    coveragedir=self.coverage_dir,
                )
                rpc.auth_service_proxy_instance.reuse_http_connections = self.reuse_http_connections
                rpc.getblockcount()

                # Wait for mempool to load
                if wait_for_import:
                    self._wait_for_mempool_load(rpc)

                self.log.debug("RPC successfully started")
                self.rpc_connected = True
                self._rpc = rpc
                self.url = rpc.rpc_url
                return

            except JSONRPCException as e:
                if e.error['code'] not in [-28, -342]:
                    raise
            except OSError:
                pass
            except ValueError as e:
                if "No RPC credentials" not in str(e):
                    raise

            time.sleep(1.0 / poll_per_s)

        self._raise_assertion_error(
            f"Unable to connect to bitcoind in container {self.container_name} "
            f"after {self.rpc_timeout}s"
        )

    def _wait_for_mempool_load(self, rpc):
        """Wait for mempool to finish loading."""
        timeout_end = time.time() + self.rpc_timeout
        while time.time() < timeout_end:
            try:
                if rpc.getmempoolinfo()['loaded']:
                    return
            except JSONRPCException:
                pass
            time.sleep(0.25)

    def _build_rpc_url(self):
        """Build the RPC URL for this container node."""
        rpc_u, rpc_p = get_auth_cookie(self.datadir_path, self.chain)
        return f"http://{rpc_u}:{rpc_p}@{self.rpc_host}:{self._rpc_port}"

    def _is_bitcoind_running(self):
        """Check if bitcoind process is running in the container."""
        try:
            result = self._exec_in_container(
                ["pgrep", "-x", "bitcoind"],
                check=False,
                timeout=10
            )
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            return False

    def stop_node(self, expected_stderr='', *, wait=0, wait_until_stopped=True):
        """Stop bitcoind in the container."""
        if not self.running:
            return

        self.log.debug(f"Stopping bitcoind in container {self.container_name}")

        # Try graceful shutdown via RPC first
        try:
            if self.rpc_connected and self._rpc:
                self.stop(wait=wait)
        except Exception as e:
            self.log.debug(f"RPC stop failed: {e}, trying pkill")
            # Fall back to pkill
            try:
                self._exec_in_container(
                    ["pkill", "-SIGTERM", "bitcoind"],
                    check=False,
                    timeout=10
                )
            except subprocess.TimeoutExpired:
                self.log.warning("pkill timed out")

        del self.p2ps[:]

        if wait_until_stopped:
            self.wait_until_stopped()

    def is_node_stopped(self, *, expected_stderr="", expected_ret_code=0):
        """Check if bitcoind has stopped in the container."""
        if not self.running:
            return True

        if self._is_bitcoind_running():
            return False

        # Process has stopped
        self.running = False
        self.process = None
        self.rpc_connected = False
        self._rpc = None
        self.log.debug("Node stopped")
        return True

    def wait_until_stopped(self, *, timeout=BITCOIND_PROC_WAIT_TIMEOUT, expect_error=False, **kwargs):
        """Wait for bitcoind to stop in the container."""
        self.wait_until(lambda: self.is_node_stopped(**kwargs), timeout=timeout)

    def kill_process(self):
        """Force kill bitcoind in the container."""
        try:
            self._exec_in_container(
                ["pkill", "-9", "bitcoind"],
                check=False,
                timeout=10
            )
        except subprocess.TimeoutExpired:
            self.log.warning("pkill -9 timed out")

        self.wait_until_stopped()
        assert self.is_node_stopped()

    def add_p2p_connection(self, p2p_conn, *, wait_for_verack=True, send_version=True,
                           supports_v2_p2p=None, wait_for_v2_handshake=True,
                           expect_success=True, **kwargs):
        """Add an inbound p2p connection to the node.

        Override to use container's P2P host instead of 127.0.0.1.
        """
        if 'dstport' not in kwargs:
            kwargs['dstport'] = self._p2p_port
        if 'dstaddr' not in kwargs:
            kwargs['dstaddr'] = self.p2p_host

        # Call parent implementation with our overridden values
        return super().add_p2p_connection(
            p2p_conn,
            wait_for_verack=wait_for_verack,
            send_version=send_version,
            supports_v2_p2p=supports_v2_p2p,
            wait_for_v2_handshake=wait_for_v2_handshake,
            expect_success=expect_success,
            **kwargs
        )

    @property
    def chain_path(self) -> Path:
        return self.datadir_path / self.chain

    @property
    def debug_log_path(self) -> Path:
        return self.chain_path / 'debug.log'

    @property
    def blocks_path(self) -> Path:
        return self.chain_path / "blocks"

    @property
    def wallets_path(self) -> Path:
        return self.chain_path / "wallets"

    def version_is_at_least(self, ver):
        """Container nodes are assumed to be latest version."""
        return True

    def get_wallet_rpc(self, wallet_name):
        """Get RPC proxy for a specific wallet."""
        import urllib.parse
        assert self.rpc_connected and self._rpc, self._node_msg("RPC not connected")
        wallet_path = "wallet/{}".format(urllib.parse.quote(wallet_name))
        return self._rpc / wallet_path
