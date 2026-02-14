import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {HashRouter, Routes, Route } from "react-router-dom";
import { AuthProvider } from "@/contexts/AuthContext";
import Index from "./pages/Index";
import Register from "./pages/Register";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import Invest from "./pages/Invest";
import Payment from "./pages/Payment";
import Referrals from "./pages/Referrals";
import Withdraw from "./pages/Withdraw";
import AdminOverview from "./pages/admin/AdminOverview";
import AdminPayments from "./pages/admin/AdminPayments";
import AdminUsers from "./pages/admin/AdminUsers";
import AdminInvestments from "./pages/admin/AdminInvestments";
import AdminWithdrawals from "./pages/admin/AdminWithdrawals";
import NotFound from "./pages/NotFound";

const queryClient = new QueryClient();

const App = () => (
  <QueryClientProvider client={queryClient}>
    <AuthProvider>
      <TooltipProvider>
        <Toaster />
        <Sonner />
        <HashRouter>
          <Routes>
            <Route path="/" element={<Index />} />
            <Route path="/register" element={<Register />} />
            <Route path="/login" element={<Login />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/invest" element={<Invest />} />
            <Route path="/payment" element={<Payment />} />
            <Route path="/referrals" element={<Referrals />} />
            <Route path="/withdraw" element={<Withdraw />} />
            <Route path="/admin/login" element={<Login />} />
            <Route path="/admin" element={<AdminOverview />} />
            <Route path="/admin/users" element={<AdminUsers />} />
            <Route path="/admin/investments" element={<AdminInvestments />} />
            <Route path="/admin/payments" element={<AdminPayments />} />
            <Route path="/admin/withdrawals" element={<AdminWithdrawals />} />
            <Route path="*" element={<NotFound />} />
          </Routes>
        </HashRouter>
      </TooltipProvider>
    </AuthProvider>
  </QueryClientProvider>
);

export default App;
