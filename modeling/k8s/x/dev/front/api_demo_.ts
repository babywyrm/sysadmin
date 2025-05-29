// beta
//

import axios from "axios";
const API = axios.create({
  baseURL: "https://project-x.example.com",
  withCredentials: true,       // send HttpOnly cookie if used
});
API.interceptors.request.use(cfg => {
  const token = localStorage.getItem("jwt");
  if (token) cfg.headers!["Authorization"] = `Bearer ${token}`;
  return cfg;
});
export default API;

// usage in Login.tsx
async function login(email: string, pwd: string) {
  const res = await API.post("/auth/login", { email, password: pwd });
  const { token } = res.data;
  localStorage.setItem("jwt", token);
}

// spawning a challenge
async function spawn(type: string, tier: string) {
  const res = await API.post("/api/challenges", { challengeType: type, tier });
  return res.data; // { id, endpoint, expiresAt, token }
}

//
//
