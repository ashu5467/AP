import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  stages: [
    { duration: '10s', target: 20 }, // Ramp up to 20 users
    { duration: '30s', target: 20 }, // Hold at 20 users for 30s
    { duration: '10s', target: 0 },  // Ramp down to 0 users
  ],
  thresholds: {
    http_req_duration: ['p(95)<500'], // 95% of requests must complete below 500ms
    http_req_failed: ['rate<0.01'],   // Less than 1% of requests can fail
  },
};

const BASE_URL = 'http://localhost:5000/api/auth';

export default function () {
  // Generate a highly unique email to avoid database collisions during heavy load
  const uniqueId = `user_${__VU}_${__ITER}_${Date.now()}`;
  const payload = JSON.stringify({
    name: `Test User ${uniqueId}`,
    email: `${uniqueId}@example.com`,
    password: 'Password123!',
  });

  const params = {
    headers: {
      'Content-Type': 'application/json',
    },
  };

  // 1. Registration Flow
  const registerRes = http.post(`${BASE_URL}/register`, payload, params);
  
  check(registerRes, {
    'registered successfully (201)': (r) => r.status === 201,
  });

  let accessToken = '';
  if (registerRes.status === 201) {
    const body = registerRes.json();
    accessToken = body.data?.accessToken;
  } else {
    console.log('Register failed:', registerRes.status, registerRes.body);
  }

  // 2. Login Flow
  const loginPayload = JSON.stringify({
    email: `${uniqueId}@example.com`,
    password: 'Password123!',
  });

  const loginRes = http.post(`${BASE_URL}/login`, loginPayload, params);
  
  check(loginRes, {
    'logged in successfully (200)': (r) => r.status === 200,
  });

  if (loginRes.status === 200) {
    const body = loginRes.json();
    accessToken = body.data?.accessToken || accessToken;
  } else {
    console.log('Login failed:', loginRes.status, loginRes.body);
  }

  // 3. Protected Route Access
  if (accessToken) {
    const authParams = {
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${accessToken}`,
      },
    };

    const meRes = http.get(`${BASE_URL}/me`, authParams);
    check(meRes, {
      'profile fetched successfully (200)': (r) => r.status === 200,
    });
  }

  // Simulate a short wait before the virtual user iterates again
  sleep(1);
}
