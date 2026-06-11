"use client";

import React, { useState } from "react";
import { signIn } from "next-auth/react";
import { Button } from "../../components/ui/button";
import { Card } from "../../components/ui/card";

export default function LoginPage() {
  const [isLoading, setIsLoading] = useState(false);

  const handleOAuthSignIn = async (provider: "google") => {
    setIsLoading(true);
    try {
      await signIn(provider, { redirect: true, callbackUrl: "/" });
    } catch (err) {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-zinc-950 text-slate-100 flex items-center justify-center overflow-hidden">
      {/* Animated background grid */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-0 left-1/4 w-96 h-96 bg-indigo-500 rounded-full mix-blend-multiply filter blur-3xl opacity-5 animate-pulse" />
        <div className="absolute bottom-0 right-1/4 w-96 h-96 bg-sky-400 rounded-full mix-blend-multiply filter blur-3xl opacity-5 animate-pulse" />
        <div
          className="absolute inset-0 opacity-5"
          style={{
            backgroundImage: "linear-gradient(0deg, transparent 24%, rgba(99, 102, 241, 0.05) 25%, rgba(99, 102, 241, 0.05) 26%, transparent 27%, transparent 74%, rgba(99, 102, 241, 0.05) 75%, rgba(99, 102, 241, 0.05) 76%, transparent 77%, transparent), linear-gradient(90deg, transparent 24%, rgba(99, 102, 241, 0.05) 25%, rgba(99, 102, 241, 0.05) 26%, transparent 27%, transparent 74%, rgba(99, 102, 241, 0.05) 75%, rgba(99, 102, 241, 0.05) 76%, transparent 77%, transparent)",
            backgroundSize: "50px 50px",
          }}
        />
      </div>

      {/* Main container */}
      <div className="relative z-10 w-full max-w-7xl mx-auto px-6">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 lg:gap-12 items-center">
          {/* Left: Branding Panel */}
          <div className="hidden lg:flex flex-col justify-center space-y-8">
            {/* Logo */}
            <div className="flex items-center gap-4">
              <div className="relative">
                <div className="absolute inset-0 bg-gradient-to-tr from-indigo-500 via-sky-400 to-cyan-300 rounded-2xl blur-lg opacity-50" />
                <div className="relative w-16 h-16 rounded-2xl bg-gradient-to-tr from-indigo-600 to-sky-500 flex items-center justify-center shadow-xl">
                  <svg
                    className="w-8 h-8 text-white"
                    viewBox="0 0 24 24"
                    fill="none"
                    xmlns="http://www.w3.org/2000/svg"
                  >
                    <path
                      d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 18c-4.41 0-8-3.59-8-8s3.59-8 8-8 8 3.59 8 8-3.59 8-8 8zm3.5-9c.83 0 1.5-.67 1.5-1.5S16.33 8 15.5 8 14 8.67 14 9.5s.67 1.5 1.5 1.5zm-7 0c.83 0 1.5-.67 1.5-1.5S9.33 8 8.5 8 7 8.67 7 9.5 7.67 11 8.5 11zm3.5 6.5c2.33 0 4.31-1.46 5.11-3.5H6.89c.8 2.04 2.78 3.5 5.11 3.5z"
                      fill="currentColor"
                    />
                  </svg>
                </div>
              </div>
              <div>
                <h1 className="text-3xl font-bold bg-gradient-to-r from-indigo-400 via-sky-400 to-cyan-400 bg-clip-text text-transparent">
                  EASM Scanner
                </h1>
                <p className="text-sm text-slate-400 font-medium">Enterprise Security Platform</p>
              </div>
            </div>

            {/* Tagline */}
            <div className="space-y-3">
              <h2 className="text-4xl font-bold text-white leading-tight">
                Secure. Scan. Protect.
              </h2>
              <p className="text-lg text-slate-400 max-w-sm leading-relaxed">
                Enterprise-grade external attack surface monitoring. Discover your public exposure and act faster than
                threats.
              </p>
            </div>

            {/* Features */}
            <div className="space-y-3 pt-4">
              {[
                "Continuous asset discovery",
                "Real-time vulnerability scanning",
                "Centralized risk assessment",
                "Compliance-ready reporting",
              ].map((feature) => (
                <div key={feature} className="flex items-center gap-3">
                  <div className="w-1.5 h-1.5 rounded-full bg-sky-400" />
                  <span className="text-sm text-slate-300">{feature}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Right: Login Form */}
          <div className="flex items-center justify-center">
            <Card className="w-full max-w-md rounded-3xl p-8 bg-zinc-900/80 backdrop-blur border border-zinc-800/50 shadow-2xl hover:border-zinc-700/50 transition-colors">
              {/* Header */}
              <div className="mb-8">
                <h3 className="text-2xl font-bold text-white">Welcome back</h3>
                <p className="text-sm text-slate-400 mt-1">Sign in to your account to continue</p>
              </div>

              {/* OAuth Buttons */}
              <div className="space-y-3 mb-6">
                {/* Google Sign-In */}
                <button
                  onClick={() => handleOAuthSignIn("google")}
                  disabled={isLoading}
                  className="w-full inline-flex items-center justify-center gap-2 px-4 py-3 rounded-lg bg-white text-black hover:bg-slate-100 disabled:opacity-50 disabled:cursor-not-allowed transition-colors font-medium text-sm"
                >
                  <svg className="w-5 h-5" viewBox="0 0 24 24" fill="currentColor">
                    <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" />
                    <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" />
                    <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" />
                    <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" />
                  </svg>
                  Sign in with Google
                </button>
              </div>


              {/* No Account Text */}
              <p className="text-center text-sm text-slate-500 mt-6">
                Don't have an account?{" "}
                <span className="text-slate-300 font-medium">Contact your administrator</span>
              </p>

              {/* Security Badge */}
              <div className="mt-8 pt-6 border-t border-zinc-800/50 flex items-center justify-center gap-2 text-xs text-slate-500">
                <svg className="w-4 h-4 text-sky-400/70" fill="currentColor" viewBox="0 0 20 20">
                  <path
                    fillRule="evenodd"
                    d="M5 9V7a5 5 0 0110 0v2a2 2 0 012 2v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5a2 2 0 012-2zm8-2v2H7V7a3 3 0 016 0z"
                    clipRule="evenodd"
                  />
                </svg>
                <span>Secured by NextAuth.js</span>
              </div>
            </Card>
          </div>
        </div>
      </div>
    </div>
  );
}
