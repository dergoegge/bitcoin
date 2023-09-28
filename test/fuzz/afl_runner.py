#!/usr/bin/env python3

import argparse
import subprocess
import re
import time
import os
import typing
import sys
import tempfile
import glob
import shutil
import hashlib

log_file = sys.stdout

def main():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description='''Run afl-fuzz on multiple cores. Based on recommendations in docs/fuzzing_in_depth.md#c-using-multiple-cores.''',
    )

    parser.add_argument(
        "action",
        help="Action to perform",
        choices=["fuzz", "minimize"],
    )
    parser.add_argument(
        "target",
        help="Target for afl to fuzz (e.g. a binary or folder for nyx targets)",
    ) 
    parser.add_argument(
        "--cmplog_bin",
        help="Path to CmpLog instrumented binary. Two secondary cmplog instances will be running",
        type=str
    )
    parser.add_argument(
        "--seeds",
        help="Input folder (same as afl-fuzz -i)",
        required=True,
    )
    parser.add_argument(
        "--out",
        help="Output folder (same as afl-fuzz -o)",
        required=True
    )
    parser.add_argument(
        "--crash_dir",
        help="Directory for crashes",
        required=True,
    )
    parser.add_argument(
        "--foreign_fuzzer_queue",
        help="Working queue of another fuzzer (e.g. the corpus dir of a libFuzzer instance). Can be specified up to 32 times.",
        action="append",
    )
    parser.add_argument(
        "--cores",
        help="Number of cores to use",
        type=int,
        default=1,
    )
    parser.add_argument(
        "--dictionary",
        help="Dictionary to use",
    )
    parser.add_argument(
        "--nyx",
        help="Run in nyx-mode",
        type=bool,
    )
    parser.add_argument(
        "--log_file",
        help="Redirect std{out,err} of the fuzzing processes to this file",
    )
    parser.add_argument(
        "--minimize",
        help="Enable periodic corpus minimization",
        default=True,
        type=bool,
    )
    args = parser.parse_args()

    if args.log_file:
        global log_file
        log_file = open(args.log_file, "w")

    if args.action == "minimize":
        minimize_corpus(
            target=args.target,
            input_dir=args.seeds,
            output_dir=args.out,
            crash_dir=args.crash_dir,
            nyx=args.nyx,
            cores=args.cores
        )
        exit(0)

    if args.cores < 1:
        print("A minimum of one core is required")
        exit(1)

    if args.cmplog_bin and args.cores < 3:
        print("A minimum of three cores is required for cmplog fuzzing")
        exit(1)

    main_fuzzer, secondary_fuzzers = start_fuzzers(args)

    # Wait for processes to finish/crash or ctrl-C.
    try:
        while True:
            secondary_fuzzers = poll_fuzzers(main=main_fuzzer, secondaries=secondary_fuzzers)
            # TODO we could restart secondary fuzzers that crashed

            # Check if we should minimize the corpus
            cycles_without_finds = afl_whatsup(output_dir=args.out)["cycles_without_finds"]
            if args.minimize and len(cycles_without_finds) > 0 and cycles_without_finds[0] >= 3:
                # The main fuzzer had more than 3 cycles without any finds
                # TODO: "3 cycles without finds" is somewhat arbitrary
                print("Cycles without finds:", cycles_without_finds)

                # Stop all fuzzers
                shutdown_fuzzers(main=main_fuzzer, secondaries=secondary_fuzzers)

                # Minimize the corpus
                minimize_corpus(
                    target=args.target,
                    input_dir=args.seeds,
                    output_dir=args.out,
                    crash_dir=args.crash_dir,
                    nyx=args.nyx,
                    cores=args.cores
                )

                # Restart the fuzzers
                main_fuzzer, secondary_fuzzers = start_fuzzers(args)

            collect_crashes(args.output_dir, args.crash_dir)
            # Sleep a while before polling and checking for minimization again
            time.sleep(60)

    except KeyboardInterrupt:
        # Kill all fuzzers on ctrl-c
        shutdown_fuzzers(main=main_fuzzer, secondaries=secondary_fuzzers)

# Check if fuzzer are still running. Exits if the main fuzzer is dead. Returns
# the secondary fuzzers that are still running.
def poll_fuzzers(main: typing.Optional[subprocess.Popen], secondaries: list):
    if main is not None:
        err = main.poll()
        if err is not None:
            print("Main afl-fuzz instance terminated with code:", err)
            exit(1)

    if len(secondaries) == 0:
        return []

    secondaries_still_running = []
    for i, secondary in secondaries:
        err = secondary.poll()
        if err is None:
            secondaries_still_running.append((i, secondary))
        else:
            print(f"Seconary afl-fuzz instance {i} terminated with code:", err)

    return secondaries_still_running

# Shut down the main and secondary fuzzers
def shutdown_fuzzers(main, secondaries):
    print("Shutting down all fuzzers")
    for _, sub in secondaries:
        sub.terminate()

    while len(secondaries) > 0:
        secondaries = poll_fuzzers(main=None, secondaries=secondaries)
        time.sleep(1)

    main.terminate()

# Start the main and secondary fuzzers
def start_fuzzers(args):
    main_fuzzer = fuzz_main(
        target=args.target,
        input_dir=args.seeds,
        output_dir=args.out,
        nyx=args.nyx,
        dictionary=args.dictionary,
        foreign_queues=args.foreign_fuzzer_queue,
    )

    print("Waiting for main afl-fuzz instance...")

    # Wait for the main fuzzer to start without error, then start the secondary fuzzers.
    while True:
        if afl_whatsup(args.out)["fuzzers_alive"] > 0:
            break

        # Poll the main fuzzer and exit if it failed to start.
        poll_fuzzers(main=main_fuzzer, secondaries=[])
        time.sleep(1)

    print("Main afl-fuzz instance has started.")
    num_fuzzers = 1
    secondary_fuzzers = []

    if args.cmplog_bin:
        print("Starting CmpLog fuzzers...")
        secondary_fuzzers.append((
            num_fuzzers,
            fuzz_secondary(
                num_fuzzers,
                target=args.target,
                input_dir=args.seeds,
                output_dir=args.out,
                nyx=args.nyx,
                dictionary=args.dictionary,
                cmplog_bin=args.cmplog_bin,
            )
        ))
        num_fuzzers += 1
        secondary_fuzzers.append((
            num_fuzzers,
            fuzz_secondary(
                num_fuzzers,
                target=args.target,
                input_dir=args.seeds,
                output_dir=args.out,
                nyx=args.nyx,
                dictionary=args.dictionary,
                cmplog_bin=args.cmplog_bin,
            )
        ))
        num_fuzzers += 1

    print("Starting secondary instances...")
    for i in range(num_fuzzers, args.cores):
        secondary_fuzzers.append((
            i,
            fuzz_secondary(
                i,
                target=args.target,
                input_dir=args.seeds,
                output_dir=args.out,
                nyx=args.nyx,
                dictionary=args.dictionary,
                cmplog_bin=None,
            )
        ))

    print("Secondary afl-fuzz instances have started.")
    return main_fuzzer, secondary_fuzzers

def get_afl_binary(name: str):
    path = os.environ["AFL_BIN_PATH"]
    if len(path) == 0:
        return name

    return str(os.path.join(path, name))

def get_fuzz_env():
    env = os.environ.copy()
    env["AFL_NO_UI"] = "1"
    env["AFL_SKIP_CPUFREQ"] = "1"
    return env

def afl_whatsup(output_dir: str):
    results = {
        "fuzzers_alive": 0,
        "crashes_saved": 0,
        "cycles_without_finds": [],
    }

    args = [get_afl_binary("afl-whatsup"), "-s", output_dir]
    whatsup = subprocess.run(args, capture_output=True, text=True)

    if whatsup.returncode != 0:
        return results 

    output = whatsup.stdout

    alive_text = re.findall("Fuzzers alive : .*", output)
    assert(len(alive_text) > 0)
    results["fuzzers_alive"] = int(alive_text[0].split(":")[1])

    crashes_text = re.findall("Crashes saved : .*", output)
    assert(len(crashes_text) > 0)
    results["crashes_saved"] = int(crashes_text[0].split(":")[1])

    cycles_text = re.findall("Cycles without finds : .*", output)
    assert(len(cycles_text) > 0)
    try:
        results["cycles_without_finds"] = list(map(lambda x: int(x), cycles_text[0].split(":")[1].split("/")))
    except ValueError:
        results["cycles_without_finds"] = []

    return results

# Start the main fuzzer
def fuzz_main(target: str, input_dir: str, output_dir: str, nyx: bool, dictionary: str, foreign_queues: typing.Optional[list]):
    args = [
        get_afl_binary("afl-fuzz"),
        "-t", "5000",
        "-i", input_dir, "-o", output_dir,
    ]

    if dictionary is not None and len(dictionary) > 0:
        args += ["-x", dictionary]

    if nyx:
        args.append("-Y")

    args += ["-M", "0"]

    if foreign_queues:
        for foreign_queue in foreign_queues:
            args += ["-F", foreign_queue]

    args += ["--", target]

    return subprocess.Popen(args, env=get_fuzz_env(), text=True, stdout=log_file, stderr=log_file)

# Start a secondary fuzzer
def fuzz_secondary(i: int, target: str, input_dir: str, output_dir: str, nyx: bool, dictionary: str, cmplog_bin: typing.Optional[str]):
    args = [
        get_afl_binary("afl-fuzz"),
        "-t", "5000",
        "-i", input_dir, "-o", output_dir,
    ]

    if dictionary is not None and len(dictionary) > 0:
        args += ["-x", dictionary]

    if cmplog_bin is not None:
        args += ["-c", cmplog_bin]

        if i % 2 == 0:
            # Some extra opts recommended by the docs
            args += ["-l", "2AT"]
    else:
        # Extra options for some secondaries, as recommended in
        # https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/fuzzing_in_depth.md#c-using-multiple-cores
        power_schedules = ["explore", "coe", "lin", "quad", "exploit", "rare"]
        if i % 2 == 0:
            # 50% of secondaries will run with a different power schedule (the default is "fast")
            args += ["-p", power_schedules[int(i/2) % len(power_schedules)]]
        if i % 10 == 0:
            # 10% will run with the old queue cycle
            args += ["-Z"]
        if i % 4 == 0:
            # A quarter runs with the MOpt mutator enabled
            args += ["-L", "0"]

    if nyx:
        args.append("-Y")

    args += [
        "-S", str(i),
        "--", target,
    ]

    return subprocess.Popen(args, env=get_fuzz_env(), text=True, stdout=log_file, stderr=log_file)

# Utility to get the sha1 hash of a file
def get_sha1_digest(file_path):
    h = hashlib.sha1()

    with open(file_path, 'rb') as file:
        while True:
            # Reading is buffered, so we can read smaller chunks.
            chunk = file.read(h.block_size)
            if not chunk:
                break
            h.update(chunk)

    return h.hexdigest() 

def collect_crashes(output_dir: str, crash_dir: str):
    # Copy all crashes
    for crash in glob.glob(os.path.join(output_dir, "*", "crashes", "*")) :
        shutil.copyfile(crash, os.path.join(crash_dir, get_sha1_digest(crash)))

# Aggregates all input queues from `output_dir` and minimizes the resulting
# corpus into `input_dir`.
def minimize_corpus(target: str, input_dir: str, output_dir: str, crash_dir: str, nyx: bool, cores: int):
    print("Minimizing corpus...")

    all_inputs = tempfile.TemporaryDirectory()
    minimized_corpus = tempfile.TemporaryDirectory()

    # Copy all inputs into `all_inputs`.
    for input_in_queue in glob.glob(os.path.join(output_dir, "*", "queue", "*")) :
        shutil.copyfile(input_in_queue, os.path.join(all_inputs.name, get_sha1_digest(input_in_queue)))

    collect_crashes(output_dir, crash_dir)

    # Run afl-cmin
    cmin_args = [
        get_afl_binary("afl-cmin"),
        "-i", all_inputs.name,
        "-o", minimized_corpus.name,
        "-T", str(cores), # utilise multiple cores
    ]

    if nyx:
        cmin_args.append("-X")

    cmin_args += ["--", target]

    env = os.environ.copy()
    env["AFL_NO_UI"] = "1"

    cmin = subprocess.run(cmin_args, env=env, text=True, stdout=log_file, stderr=log_file)

    if cmin.returncode != 0:
        print("Minimizing with afl-cmin failed")
        exit(1)

    # Copy minimized_corpus to input directory
    shutil.rmtree(input_dir, ignore_errors=True)
    shutil.copytree(minimized_corpus.name, input_dir)

    # Clean up
    shutil.rmtree(output_dir, ignore_errors=True)
    all_inputs.cleanup()
    minimized_corpus.cleanup()

if __name__ == '__main__':
    main()
