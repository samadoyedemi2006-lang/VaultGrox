import { Link } from "react-router-dom";
import { motion } from "framer-motion";
import { TrendingUp, Banknote, Users, ShieldCheck, ArrowRight, ChevronRight } from "lucide-react";

const plans = [
  { name: "Starter Growth", amount: "₦2,000", roi: "15%" },
  { name: "Silver Growth", amount: "₦5,000", roi: "15%" },
  { name: "Gold Growth", amount: "₦10,000", roi: "15%" },
  { name: "Platinum Growth", amount: "₦15,000", roi: "15%" },
];

const features = [
  { icon: TrendingUp, title: "Daily ROI", desc: "Earn 15% daily return on your investments" },
  { icon: Banknote, title: "Bank Transfer Funding", desc: "Simple and secure bank transfer deposits" },
  { icon: Users, title: "Referral Rewards", desc: "Earn ₦500 for every successful referral" },
  { icon: ShieldCheck, title: "Secure Platform", desc: "Your investments are safe and monitored" },
];

export default function LandingPage() {
  return (
    <div className="min-h-screen gradient-hero">
      {/* Nav */}
      <nav className="flex items-center justify-between px-6 md:px-12 py-5 max-w-7xl mx-auto">
        <span className="text-xl font-display font-bold text-gradient">VaultGrow</span>
        <div className="flex items-center gap-3">
          <Link
            to="/login"
            className="px-5 py-2.5 text-sm font-medium text-foreground hover:text-primary transition-colors"
          >
            Login
          </Link>
          <Link
            to="/register"
            className="px-5 py-2.5 text-sm font-medium gradient-primary text-primary-foreground rounded-lg hover:opacity-90 transition-opacity"
          >
            Register
          </Link>
        </div>
      </nav>

      {/* Hero */}
      <section className="relative px-6 md:px-12 pt-16 pb-24 max-w-7xl mx-auto text-center overflow-hidden">
        <div className="gradient-glow absolute inset-0 pointer-events-none" />
        <motion.h1
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.7 }}
          className="text-4xl md:text-6xl lg:text-7xl font-display font-bold text-foreground leading-tight relative"
        >
          Grow Your Money{" "}
          <span className="text-gradient">Smarter, Daily</span>
        </motion.h1>
        <motion.p
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2, duration: 0.6 }}
          className="mt-6 text-lg md:text-xl text-muted-foreground max-w-2xl mx-auto relative"
        >
          Invest as low as ₦2,000 and earn 15% daily returns. Fund via bank transfer, withdraw anytime.
        </motion.p>
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4, duration: 0.5 }}
          className="mt-10 flex flex-col sm:flex-row items-center justify-center gap-4 relative"
        >
          <Link
            to="/register"
            className="px-8 py-4 gradient-primary text-primary-foreground rounded-xl font-semibold text-lg shadow-glow hover:opacity-90 transition-all flex items-center gap-2"
          >
            Get Started <ArrowRight className="h-5 w-5" />
          </Link>
          <Link
            to="/login"
            className="px-8 py-4 border border-border text-foreground rounded-xl font-semibold text-lg hover:bg-secondary transition-all"
          >
            Login to Dashboard
          </Link>
        </motion.div>
      </section>

      {/* Features */}
      <section className="px-6 md:px-12 py-20 max-w-7xl mx-auto">
        <h2 className="text-2xl md:text-3xl font-display font-bold text-center text-foreground mb-12">
          Why Choose VaultGrow?
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {features.map((f, i) => (
            <motion.div
              key={f.title}
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ delay: i * 0.1, duration: 0.5 }}
              className="gradient-card border border-border rounded-xl p-6 shadow-card hover:shadow-glow transition-shadow"
            >
              <div className="h-12 w-12 rounded-lg gradient-primary flex items-center justify-center mb-4">
                <f.icon className="h-6 w-6 text-primary-foreground" />
              </div>
              <h3 className="font-display font-semibold text-foreground mb-2">{f.title}</h3>
              <p className="text-sm text-muted-foreground">{f.desc}</p>
            </motion.div>
          ))}
        </div>
      </section>

      {/* Plans Preview */}
      <section className="px-6 md:px-12 py-20 max-w-7xl mx-auto">
        <h2 className="text-2xl md:text-3xl font-display font-bold text-center text-foreground mb-4">
          Investment Plans
        </h2>
        <p className="text-center text-muted-foreground mb-12">Choose a plan that suits your budget</p>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
          {plans.map((plan, i) => (
            <motion.div
              key={plan.name}
              initial={{ opacity: 0, scale: 0.95 }}
              whileInView={{ opacity: 1, scale: 1 }}
              viewport={{ once: true }}
              transition={{ delay: i * 0.1 }}
              className="gradient-card border border-border rounded-xl p-6 shadow-card text-center hover:shadow-glow transition-shadow group"
            >
              <h3 className="font-display font-semibold text-foreground mb-1">{plan.name}</h3>
              <p className="text-3xl font-display font-bold text-gradient my-4">{plan.amount}</p>
              <p className="text-sm text-muted-foreground mb-6">Daily ROI: {plan.roi}</p>
              <Link
                to="/register"
                className="inline-flex items-center gap-1 text-sm font-medium text-primary hover:underline"
              >
                Start Investing <ChevronRight className="h-4 w-4" />
              </Link>
            </motion.div>
          ))}
        </div>
      </section>

      {/* Disclaimer */}
      <section className="px-6 md:px-12 py-12 max-w-3xl mx-auto">
        <div className="glass-card rounded-xl p-6 text-center">
          <p className="text-sm text-muted-foreground">
            <strong className="text-foreground">Disclaimer:</strong> All investment earnings depend on admin
            confirmation. Returns are subject to platform policies. Invest responsibly.
          </p>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-border px-6 md:px-12 py-8 max-w-7xl mx-auto">
        <div className="flex flex-col md:flex-row items-center justify-between gap-4">
          <span className="text-sm text-muted-foreground">© 2026 VaultGrow. All rights reserved.</span>
          <div className="flex items-center gap-6 text-sm text-muted-foreground">
            <Link to="/login" className="hover:text-foreground transition-colors">Login</Link>
            <Link to="/register" className="hover:text-foreground transition-colors">Register</Link>
            <Link to="/admin/login" className="hover:text-foreground transition-colors">Admin</Link>
          </div>
        </div>
      </footer>
    </div>
  );
}
