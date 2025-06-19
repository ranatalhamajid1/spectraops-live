const autocannon = require('autocannon');
const { performance } = require('perf_hooks');

class LoadTester {
    constructor() {
        this.baseUrl = process.env.TEST_URL || 'http://localhost:3000';
        this.results = [];
    }

    async runBasicLoadTest() {
        console.log('🚀 Starting basic load test...');
        
        const result = await autocannon({
            url: this.baseUrl,
            connections: 10,
            pipelining: 1,
            duration: 30
        });

        this.analyzeResults('Basic Load Test', result);
        return result;
    }

    async runStressTest() {
        console.log('💪 Starting stress test...');
        
        const result = await autocannon({
            url: this.baseUrl,
            connections: 100,
            pipelining: 10,
            duration: 60
        });

        this.analyzeResults('Stress Test', result);
        return result;
    }

    async runSecurityToolsLoadTest() {
        console.log('🔐 Testing security tools under load...');
        
        const endpoints = [
            '/api/security/check-email',
            '/api/security/scan-url',
            '/api/security/analyze-password'
        ];

        const results = [];
        
        for (const endpoint of endpoints) {
            const result = await autocannon({
                url: `${this.baseUrl}${endpoint}`,
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(this.getTestData(endpoint)),
                connections: 20,
                duration: 30
            });
            
            results.push({ endpoint, result });
            this.analyzeResults(`Security Tool: ${endpoint}`, result);
        }

        return results;
    }

    async runDatabaseLoadTest() {
        console.log('💾 Testing database under load...');
        
        const result = await autocannon({
            url: `${this.baseUrl}/api/contact`,
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                name: 'Load Test User',
                email: 'loadtest@example.com',
                subject: 'Load Testing',
                message: 'This is a load test message',
                captchaAnswer: '5'
            }),
            connections: 50,
            duration: 45
        });

        this.analyzeResults('Database Load Test', result);
        return result;
    }

    getTestData(endpoint) {
        const testData = {
            '/api/security/check-email': {
                email: 'test@example.com'
            },
            '/api/security/scan-url': {
                url: 'https://example.com'
            },
            '/api/security/analyze-password': {
                password: 'TestPassword123!'
            }
        };

        return testData[endpoint] || {};
    }

    analyzeResults(testName, result) {
        const analysis = {
            testName,
            timestamp: new Date().toISOString(),
            requestsPerSecond: result.requests.average,
            latency: {
                average: result.latency.average,
                p95: result.latency.p95,
                p99: result.latency.p99
            },
            throughput: result.throughput.average,
            errors: result.errors,
            timeouts: result.timeouts,
            duration: result.duration,
            passed: this.determineIfPassed(result)
        };

        this.results.push(analysis);
        
        console.log(`\n📊 ${testName} Results:`);
        console.log(`   Requests/sec: ${analysis.requestsPerSecond}`);
        console.log(`   Avg Latency: ${analysis.latency.average}ms`);
        console.log(`   P95 Latency: ${analysis.latency.p95}ms`);
        console.log(`   P99 Latency: ${analysis.latency.p99}ms`);
        console.log(`   Throughput: ${analysis.throughput} bytes/sec`);
        console.log(`   Errors: ${analysis.errors}`);
        console.log(`   Status: ${analysis.passed ? '✅ PASSED' : '❌ FAILED'}`);
    }

    determineIfPassed(result) {
        // Performance criteria
        const criteria = {
            maxLatencyP95: 500, // ms
            minRequestsPerSecond: 100,
            maxErrorRate: 0.01 // 1%
        };

        const errorRate = result.errors / result.requests.total;
        
        return (
            result.latency.p95 <= criteria.maxLatencyP95 &&
            result.requests.average >= criteria.minRequestsPerSecond &&
            errorRate <= criteria.maxErrorRate
        );
    }

    async runCompleteTestSuite() {
        console.log('🧪 Running complete load test suite...\n');
        
        const startTime = performance.now();
        
        await this.runBasicLoadTest();
        await new Promise(resolve => setTimeout(resolve, 5000)); // Cool down
        
        await this.runStressTest();
        await new Promise(resolve => setTimeout(resolve, 5000));
        
        await this.runSecurityToolsLoadTest();
        await new Promise(resolve => setTimeout(resolve, 5000));
        
        await this.runDatabaseLoadTest();
        
        const endTime = performance.now();
        const totalDuration = Math.round(endTime - startTime);
        
        this.generateReport(totalDuration);
    }

    generateReport(totalDuration) {
        console.log('\n📋 Load Test Report');
        console.log('='.repeat(50));
        console.log(`Total Test Duration: ${totalDuration}ms`);
        console.log(`Tests Completed: ${this.results.length}`);
        console.log(`Tests Passed: ${this.results.filter(r => r.passed).length}`);
        console.log(`Tests Failed: ${this.results.filter(r => !r.passed).length}`);
        
        const overallPass = this.results.every(r => r.passed);
        console.log(`\nOverall Status: ${overallPass ? '✅ ALL TESTS PASSED' : '❌ SOME TESTS FAILED'}`);
        
        if (!overallPass) {
            console.log('\n❌ Failed Tests:');
            this.results
                .filter(r => !r.passed)
                .forEach(r => console.log(`   - ${r.testName}`));
        }

        // Save detailed report
        const fs = require('fs');
        const reportPath = `./load-test-report-${Date.now()}.json`;
        fs.writeFileSync(reportPath, JSON.stringify({
            summary: {
                totalDuration,
                testsCompleted: this.results.length,
                testsPassed: this.results.filter(r => r.passed).length,
                testsFailed: this.results.filter(r => !r.passed).length,
                overallPass
            },
            results: this.results
        }, null, 2));
        
        console.log(`\n📄 Detailed report saved: ${reportPath}`);
    }
}

// Run tests if called directly
if (require.main === module) {
    const tester = new LoadTester();
    tester.runCompleteTestSuite().catch(console.error);
}

module.exports = LoadTester;