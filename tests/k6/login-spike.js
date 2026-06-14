import http from 'k6/http';
import { check } from 'k6';

export const options = {
  stages: [
    { duration: '5s', target: 100 }, // Spike to 100 virtual users instantly
    { duration: '15s', target: 100 }, // Hold the aggressive spike
    { duration: '5s', target: 0 },   // Scale down
  ],
};

const BASE_URL = 'http://localhost:5000/api/auth';

export default function () {
  const payload = JSON.stringify({
    email: `spike_${__VU}_${__ITER}@example.com`,
    password: 'Password123!',
  });

  const params = {
    headers: {
      'Content-Type': 'application/json',
    },
  };

  // Aggressively hitting the login endpoint to test Express rate-limiting and DB pooling
  const loginRes = http.post(`${BASE_URL}/login`, payload, params);
  
  // We expect the server to either reject the login (because user doesn't exist)
  // OR return a 429 Too Many Requests once the rate limiter kicks in.
  check(loginRes, {
    'is handled properly (401/404/429)': (r) => r.status === 429 || r.status === 401 || r.status === 404,
    'rate limit triggered (429)': (r) => r.status === 429,
  });
}
