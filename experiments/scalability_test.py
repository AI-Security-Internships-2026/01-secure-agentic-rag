import json
import time
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
import statistics

# Ensure the parent directory is in the path so we can import src
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.data_functions.query_engine import query_rag_system

def load_questions(filepath):
    with open(filepath, 'r') as f:
        return json.load(f)

def run_single_query(question):
    start_time = time.time()
    try:
        response = query_rag_system(
            collection_name=question["collection_name"],
            query=question["query"],
            n_results=5,
            user_id="admin",
            filtering_mode="none"
        )
        success = True
    except Exception as e:
        response = str(e)
        success = False
    end_time = time.time()
    return {
        "time": end_time - start_time,
        "success": success,
        "response": response
    }

def run_sequential_test(questions, delay_between_requests=1.0):
    print(f"\n--- Running Sequential Test ({len(questions)} queries) ---")
    results = []
    total_start = time.time()
    
    for i, q in enumerate(questions):
        print(f"Processing query {i+1}/{len(questions)}...")
        res = run_single_query(q)
        results.append(res)
        if not res["success"]:
            print(f"  -> Error: {res['response']}")
        time.sleep(delay_between_requests)

    total_time = time.time() - total_start
    print_metrics(results, total_time)

def run_concurrent_test(questions, max_workers=5):
    print(f"\n--- Running Concurrent Test ({len(questions)} queries, {max_workers} workers) ---")
    results = []
    total_start = time.time()

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_q = {executor.submit(run_single_query, q): q for q in questions}
        for i, future in enumerate(as_completed(future_to_q)):
            print(f"Completed concurrent query {i+1}/{len(questions)}...")
            try:
                res = future.result()
                results.append(res)
                if not res["success"]:
                    print(f"  -> Error: {res['response']}")
            except Exception as exc:
                print(f"Query generated an exception: {exc}")
                results.append({"time": 0, "success": False, "response": str(exc)})

    total_time = time.time() - total_start
    print_metrics(results, total_time)

def print_metrics(results, total_wall_time):
    times = [r["time"] for r in results if r["success"]]
    successes = sum(1 for r in results if r["success"])
    failures = len(results) - successes
    
    print(f"\nTotal Wall Time: {total_wall_time:.2f} seconds")
    print(f"Successes: {successes}")
    print(f"Failures: {failures}")
    
    if times:
        print(f"Average Response Time: {statistics.mean(times):.2f} seconds")
        print(f"Median Response Time: {statistics.median(times):.2f} seconds")
        print(f"Min Response Time: {min(times):.2f} seconds")
        print(f"Max Response Time: {max(times):.2f} seconds")

if __name__ == "__main__":
    filepath = os.path.join(os.path.dirname(__file__), 'test_questions.json')
    questions = load_questions(filepath)
    
    # We will test 50 questions sequentially and 50 concurrently. 
    # This prevents total exhaustion of API limits while still demonstrating scalability.
    test_set_seq = questions[:50]
    test_set_conc = questions[50:]
    
    print("Starting Scalability Testing...")
    
    run_sequential_test(test_set_seq, delay_between_requests=1.0) # 1 sec delay to help with rate limits
    
    print("\nWaiting 10 seconds before concurrent test to cool down APIs...")
    time.sleep(10)
    
    run_concurrent_test(test_set_conc, max_workers=5)
