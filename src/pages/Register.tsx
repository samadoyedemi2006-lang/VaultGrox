import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import { api } from "@/lib/api";
import { Eye, EyeOff, Loader2 } from "lucide-react";
import { toast } from "sonner";

export default function RegisterPage() {
  const navigate = useNavigate();
  const [form, setForm] = useState({
    fullName: "", email: "", phone: "", password: "", confirmPassword: "", referralCode: "",
  });
  const [showPw, setShowPw] = useState(false);
  const [loading, setLoading] = useState(false);

  // Pre-fill referral code from URL query param
  useState(() => {
    const params = new URLSearchParams(window.location.search);
    const ref = params.get("ref");
    if (ref) {
      setForm((prev) => ({ ...prev, referralCode: ref }));
    }
  });

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (form.password !== form.confirmPassword) {
      toast.error("Passwords do not match");
      return;
    }
    if (form.password.length < 6) {
      toast.error("Password must be at least 6 characters");
      return;
    }
    setLoading(true);
    try {
      await api.register({
        fullName: form.fullName,
        email: form.email,
        phone: form.phone,
        password: form.password,
        referralCode: form.referralCode || undefined,
      });
      toast.success("Registration successful! Please login.");
      navigate("/login");
    } catch (err: any) {
      toast.error(err.message || "Registration failed");
    } finally {
      setLoading(false);
    }
  };

  const inputClass =
    "w-full px-4 py-3 rounded-lg bg-secondary border border-border text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary/50 transition-all";

  return (
    <div className="min-h-screen gradient-hero flex items-center justify-center p-4">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="w-full max-w-md"
      >
        <div className="text-center mb-8">
          <Link to="/" className="text-2xl font-display font-bold text-gradient">VaultGrow</Link>
          <h1 className="text-xl font-display font-semibold text-foreground mt-4">Create Your Account</h1>
        </div>

        <form onSubmit={handleSubmit} className="gradient-card border border-border rounded-2xl p-8 shadow-card space-y-4">
          <div className="glass-card rounded-lg p-3 text-center mb-2">
            <p className="text-sm text-primary font-medium">₦700 welcome bonus will be credited to your wallet after registration</p>
          </div>

          <input className={inputClass} placeholder="Full Name" required value={form.fullName} onChange={(e) => setForm({ ...form, fullName: e.target.value })} />
          <input className={inputClass} type="email" placeholder="Email Address" required value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} />
          <input className={inputClass} type="tel" placeholder="Phone Number" required value={form.phone} onChange={(e) => setForm({ ...form, phone: e.target.value })} />

          <div className="relative">
            <input className={inputClass} type={showPw ? "text" : "password"} placeholder="Password" required value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
            <button type="button" onClick={() => setShowPw(!showPw)} className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground">
              {showPw ? <EyeOff className="h-5 w-5" /> : <Eye className="h-5 w-5" />}
            </button>
          </div>

          <input className={inputClass} type={showPw ? "text" : "password"} placeholder="Confirm Password" required value={form.confirmPassword} onChange={(e) => setForm({ ...form, confirmPassword: e.target.value })} />
          <input className={inputClass} placeholder="Referral Code (optional)" value={form.referralCode} onChange={(e) => setForm({ ...form, referralCode: e.target.value })} />

          <button
            type="submit"
            disabled={loading}
            className="w-full py-3.5 rounded-lg gradient-primary text-primary-foreground font-semibold text-base hover:opacity-90 disabled:opacity-50 transition-all flex items-center justify-center gap-2"
          >
            {loading && <Loader2 className="h-5 w-5 animate-spin" />}
            Register
          </button>

          <p className="text-center text-sm text-muted-foreground">
            Already have an account?{" "}
            <Link to="/login" className="text-primary hover:underline">Login</Link>
          </p>
        </form>
      </motion.div>
    </div>
  );
}
