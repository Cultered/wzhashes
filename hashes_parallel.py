"""
Parallel bruteforce runner for hashes.py
Spawns multiple worker processes to utilize all CPU cores.
"""

import multiprocessing
import hashlib
import re
import os
import time
import sys
from dataclasses import dataclass
from typing import Optional

# Import key generation from hashes.py
try:
    from nacl.signing import SigningKey
    USE_NACL = True
except ImportError:
    USE_NACL = False
    print("Warning: PyNaCl not installed. Using fallback key generation.")
    print("Install with: pip install PyNaCl")


def base64_encode(data):
    """Encode bytes to base64 string."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    result = []

    for n in range(len(data) // 3):
        block = (data[n * 3] << 16) | (data[n * 3 + 1] << 8) | data[n * 3 + 2]
        for i in range(4):
            val = (block >> (6 * (3 - i))) & 0x3F
            result.append(alphabet[val])

    remaining = len(data) % 3
    if remaining > 0:
        block = data[len(data) // 3 * 3] << 16
        if remaining == 2:
            block |= data[len(data) // 3 * 3 + 1] << 8
        for i in range(remaining + 1):
            val = (block >> (6 * (3 - i))) & 0x3F
            result.append(alphabet[val])
        for i in range(3 - remaining):
            result.append("=")

    return "".join(result)


def generate_ed25519_keypair():
    """Generate an Ed25519 keypair."""
    if USE_NACL:
        signing_key = SigningKey.generate()
        seed = bytes(signing_key)
        public_key = bytes(signing_key.verify_key)
        private_key = seed + public_key
        return public_key, private_key
    else:
        seed = os.urandom(32)
        public_key = hashlib.sha256(seed).digest()[:32]
        private_key = seed + public_key
        return public_key, private_key


def worker_bruteforce(worker_id: int, regex_pattern: str, result_queue: multiprocessing.Queue, 
                       stop_event: multiprocessing.Event, stats_queue: multiprocessing.Queue):
    """
    Worker function that runs in each process.
    
    Args:
        worker_id: Unique ID for this worker
        regex_pattern: Regex pattern to match
        result_queue: Queue to put results when found
        stop_event: Event to signal workers to stop
        stats_queue: Queue to report statistics
    """
    pattern = re.compile(regex_pattern)
    attempts = 0
    last_report = time.time()
    report_interval = 5.0  # Increased from 2 to reduce overhead
    
    # Batch processing - check stop event less frequently
    batch_size = 1000  # Process 1000 keys before checking stop event
    
    try:
        while not stop_event.is_set():
            # Process in batches to reduce overhead
            for _ in range(batch_size):
                # Generate Ed25519 keypair
                public_key, private_key = generate_ed25519_keypair()
                
                # Get SHA256 hash of public key
                hash_str = hashlib.sha256(public_key).hexdigest()
                
                attempts += 1
                
                # Check if hash matches pattern
                if pattern.search(hash_str):
                    result_queue.put({
                        "worker_id": worker_id,
                        "private_key": private_key,
                        "public_key": public_key,
                        "hash": hash_str,
                    })
                    stop_event.set()
                    # Report final stats before returning
                    if attempts > 0:
                        stats_queue.put((worker_id, attempts))
                    return
            
            # Report stats less frequently to reduce overhead
            now = time.time()
            if now - last_report >= report_interval:
                stats_queue.put((worker_id, attempts))
                attempts = 0
                last_report = now
                
    except KeyboardInterrupt:
        pass
    finally:
        # Report final stats
        if attempts > 0:
            stats_queue.put((worker_id, attempts))


def run_parallel_bruteforce(regex_pattern: str, num_workers: Optional[int] = None):
    """
    Run parallel bruteforce with multiple processes.
    
    Args:
        regex_pattern: Regex pattern to match against SHA256 hash
        num_workers: Number of worker processes (defaults to CPU count)
    """
    if num_workers is None:
        # Use 2x CPU count for better utilization
        num_workers = multiprocessing.cpu_count() * 2
    
    print(f"\n{'=' * 60}")
    print("PARALLEL BRUTEFORCE VANITY KEY GENERATOR")
    print(f"{'=' * 60}")
    print(f"Pattern: {regex_pattern}")
    print(f"Workers: {num_workers}")
    print(f"Using {'proper Ed25519' if USE_NACL else 'fallback'} key generation")
    print("Press Ctrl+C to stop\n")
    
    # Create shared objects
    result_queue = multiprocessing.Queue()
    stats_queue = multiprocessing.Queue()
    stop_event = multiprocessing.Event()
    
    # Start worker processes
    workers = []
    for i in range(num_workers):
        p = multiprocessing.Process(
            target=worker_bruteforce,
            args=(i, regex_pattern, result_queue, stop_event, stats_queue)
        )
        p.start()
        workers.append(p)
    
    print(f"Started {num_workers} worker processes\n")
    
    # Monitor progress
    start_time = time.time()
    total_attempts = 0
    worker_attempts = {i: 0 for i in range(num_workers)}
    
    try:
        while not stop_event.is_set():
            # Check for results
            try:
                result = result_queue.get_nowait()
                elapsed = time.time() - start_time
                
                # Collect remaining stats
                while not stats_queue.empty():
                    try:
                        worker_id, count = stats_queue.get_nowait()
                        worker_attempts[worker_id] += count
                    except:
                        break
                
                total_attempts = sum(worker_attempts.values())
                
                print(f"\n{'=' * 60}")
                print(f"✓ MATCH FOUND by Worker {result['worker_id']}!")
                print(f"{'=' * 60}")
                print(f"Time elapsed: {elapsed:.2f}s")
                print(f"Total attempts: {total_attempts:,}")
                print(f"Rate: {total_attempts / elapsed:.0f} keys/s")
                print(f"\nPrivate key (hex): {result['private_key'].hex()}")
                print(f"Public key (hex):  {result['public_key'].hex()}")
                print(f"Hash:              {result['hash']}")
                print(f"Private key (base64): {base64_encode(result['private_key'])}")
                
                return result
                
            except:
                pass
            
            # Collect and display stats
            while not stats_queue.empty():
                try:
                    worker_id, count = stats_queue.get_nowait()
                    worker_attempts[worker_id] += count
                except:
                    break
            
            total_attempts = sum(worker_attempts.values())
            elapsed = time.time() - start_time
            rate = total_attempts / elapsed if elapsed > 0 else 0
            
            # Print progress
            print(f"\rAttempts: {total_attempts:,} | Rate: {rate:.0f}/s | Time: {elapsed:.1f}s", end="", flush=True)
            
            time.sleep(0.5)
            
    except KeyboardInterrupt:
        print("\n\nStopping workers...")
        stop_event.set()
    
    # Wait for workers to finish
    for p in workers:
        p.join(timeout=2)
        if p.is_alive():
            p.terminate()
    
    # Final stats
    while not stats_queue.empty():
        try:
            worker_id, count = stats_queue.get_nowait()
            worker_attempts[worker_id] += count
        except:
            break
    
    total_attempts = sum(worker_attempts.values())
    elapsed = time.time() - start_time
    
    print(f"\n\nFinal Statistics:")
    print(f"Total attempts: {total_attempts:,}")
    print(f"Time elapsed: {elapsed:.2f}s")
    print(f"Average rate: {total_attempts / elapsed:.0f} keys/s")
    
    return None


if __name__ == "__main__":
    # Needed for Windows multiprocessing
    multiprocessing.freeze_support()
    
    print("\n" + "=" * 60)
    print("PARALLEL BRUTEFORCE VANITY KEY GENERATOR")
    print("=" * 60)
    
    # Get number of CPU cores
    cpu_count = multiprocessing.cpu_count()
    default_workers = cpu_count * 2  # Default to 2x cores
    
    # User input
    regex_input = input(
        "Enter regex pattern for hash (e.g., '^bfc0' for starting with bfc0): "
    ).strip()
    if not regex_input:
        regex_input = "^bfcbfc"  # Default pattern
    
    workers_input = input(f"Enter number of workers (press Enter for {default_workers} - 2x{cpu_count} cores): ").strip()
    num_workers = int(workers_input) if workers_input else default_workers
    
    result = run_parallel_bruteforce(regex_input, num_workers)
