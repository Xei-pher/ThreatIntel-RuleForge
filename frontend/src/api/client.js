import axios from 'axios';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

export const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 1000 * 60 * 10,
});

export function describeApiError(error) {
  if (error?.response) {
    const detail = error.response.data?.detail || error.response.data?.message || JSON.stringify(error.response.data || {});
    return `API ${error.response.status}: ${detail}`;
  }

  if (error?.code === 'ECONNABORTED') {
    return 'Request timed out. The backend may still be processing. Check the backend terminal logs, then refresh the report.';
  }

  if (error?.message === 'Network Error') {
    return `Network Error: frontend could not reach backend at ${API_BASE_URL}. Confirm backend is running and open ${API_BASE_URL}/health in your browser.`;
  }

  return error?.message || 'Unknown error';
}

export { API_BASE_URL };
