import boto3
import json
import concurrent.futures
import time
from datetime import datetime

def invoke_lambda(event_id):
    """Invoke Lambda function with test event"""
    lambda_client = boto3.client('lambda')
    
    test_event = {
        "source": "aws.inspector2",
        "detail-type": "Inspector2 Finding",
        "detail": {
            "resources": [{"id": f"arn:aws:ec2:us-east-1:123456789012:instance/i-test{event_id}"}],
            "severity": "HIGH",
            "status": "ACTIVE",
            "type": "PACKAGE_VULNERABILITY",
            "findingArn": f"test-finding-{event_id}",
            "timestamp": datetime.now().isoformat()
        }
    }
    
    start_time = time.time()
    try:
        response = lambda_client.invoke(
            FunctionName='patch-deduplication-function',
            Payload=json.dumps(test_event)
        )
        duration = time.time() - start_time
        return {
            'event_id': event_id,
            'duration': duration,
            'status_code': response['StatusCode'],
            'success': True
        }
    except Exception as e:
        return {
            'event_id': event_id,
            'duration': time.time() - start_time,
            'error': str(e),
            'success': False
        }

def run_load_test(concurrent_requests=10, total_requests=100):
    """Run load test against Lambda function"""
    print(f"🚀 Starting load test: {total_requests} requests, {concurrent_requests} concurrent")
    
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrent_requests) as executor:
        futures = [executor.submit(invoke_lambda, i) for i in range(total_requests)]
        
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            results.append(result)
            if len(results) % 10 == 0:
                print(f"Completed {len(results)}/{total_requests} requests")
    
    # Analyze results
    successful_requests = [r for r in results if r['success']]
    failed_requests = [r for r in results if not r['success']]
    
    if successful_requests:
        durations = [r['duration'] for r in successful_requests]
        avg_duration = sum(durations) / len(durations)
        max_duration = max(durations)
        min_duration = min(durations)
        
        print(f"\n📊 Load Test Results:")
        print(f"   Total Requests: {total_requests}")
        print(f"   Successful: {len(successful_requests)}")
        print(f"   Failed: {len(failed_requests)}")
        print(f"   Success Rate: {len(successful_requests)/total_requests*100:.1f}%")
        print(f"   Average Duration: {avg_duration:.3f}s")
        print(f"   Min Duration: {min_duration:.3f}s")
        print(f"   Max Duration: {max_duration:.3f}s")
    
    return results

if __name__ == '__main__':
    run_load_test()