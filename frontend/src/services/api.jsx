import axios from 'axios';

const API_BASE_URL = process.env.NODE_ENV === 'development' 
  ? 'http://localhost:5000/api'  // Your machine's IP address and Flask port
  : '/api';  // For production, assuming the API is on the same server

const api = axios.create({
  baseURL: API_BASE_URL,
});

export default api;