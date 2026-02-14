const API_BASE = `${import.meta.env.VITE_SUPABASE_URL}/functions/v1/api`;

interface RequestOptions {
  method?: string;
  body?: unknown;
  headers?: Record<string, string>;
}

async function request<T>(endpoint: string, options: RequestOptions = {}): Promise<T> {
  const token = localStorage.getItem("token");
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...options.headers,
  };
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  const res = await fetch(`${API_BASE}${endpoint}`, {
    method: options.method || "GET",
    headers,
    body: options.body ? JSON.stringify(options.body) : undefined,
  });

  if (!res.ok) {
    const error = await res.json().catch(() => ({ message: "Request failed" }));
    throw new Error(error.message || "Something went wrong");
  }

  return res.json();
}

export const api = {
  // Auth
  register: (data: { fullName: string; email: string; phone: string; password: string; referralCode?: string }) =>
    request("/auth/register", { method: "POST", body: data }),

  login: (data: { email: string; password: string }) =>
    request<{ token: string; user: unknown; isAdmin: boolean }>("/auth/login", { method: "POST", body: data }),

  // User
  getDashboard: () => request("/user/dashboard"),
  getTransactions: () => request("/user/transactions"),

  // Invest
  createInvestment: (data: { planId: string; amount: number }) =>
    request("/invest/create", { method: "POST", body: data }),

  // Payment
  submitPayment: (data: { amount: number; reference: string }) =>
    request("/payment/submit", { method: "POST", body: data }),

  // Referral
  getReferral: () => request("/referral"),

  // Withdraw
  requestWithdrawal: (data: { amount: number; bankName: string; accountNumber: string; accountName: string }) =>
    request("/withdraw/request", { method: "POST", body: data }),

  // Admin
  getAdminOverview: () => request("/admin/overview"),
  getAdminUsers: () => request("/admin/users"),
  toggleUserBlock: (userId: string) =>
    request(`/admin/users/${userId}/toggle-block`, { method: "PATCH" }),
  getAdminInvestments: () => request("/admin/investments"),
  confirmInvestment: (investmentId: string) =>
    request(`/admin/invest/confirm`, { method: "PATCH", body: { investmentId } }),
  getAdminWithdrawals: () => request("/admin/withdrawals"),
  approveWithdrawal: (withdrawalId: string) =>
    request(`/admin/withdraw/approve`, { method: "PATCH", body: { withdrawalId } }),
  getAdminPayments: () => request("/admin/payments"),
  triggerRoi: () => {
    const base = `${import.meta.env.VITE_SUPABASE_URL}/functions/v1/daily-roi`;
    return fetch(base, { method: "POST", headers: { "Content-Type": "application/json" } }).then(r => r.json());
  },
  confirmPayment: (paymentId: string) =>
    request(`/admin/payment/confirm`, { method: "PATCH", body: { paymentId } }),
};
