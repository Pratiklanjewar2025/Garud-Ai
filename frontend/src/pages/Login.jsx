import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Lock } from 'lucide-react';
import { Button } from '../components/ui/Button';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/Card';

export function Login() {
  const navigate = useNavigate();

  const handleLogin = (e) => {
    e.preventDefault();
    navigate('/dashboard');
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-4 relative overflow-hidden bg-background">
      {/* Glow effects */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[800px] bg-primary/10 rounded-full blur-[120px] pointer-events-none"></div>
      
      <div className="w-full max-w-md relative z-10">
        <div className="text-center mb-8">
          <div className="inline-flex p-4 rounded-full bg-surface border border-borderSubtle mb-4 shadow-[0_0_30px_rgba(37,99,235,0.2)]">
            <Shield className="w-12 h-12 text-primary" />
          </div>
          <h1 className="text-3xl font-bold tracking-widest uppercase neon-text-primary">GARUD-AI</h1>
          <p className="text-textMuted mt-2 tracking-wide uppercase text-sm">CyberShield Analysis Platform</p>
        </div>

        <Card className="glass-panel border-borderSubtle/50">
          <CardHeader className="text-center pb-2">
            <CardTitle className="text-xl">Authentication Required</CardTitle>
            <CardDescription>Enter your analyst credentials to access the platform.</CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleLogin} className="space-y-4">
              <div className="space-y-2">
                <label className="text-sm font-medium text-textMuted">Analyst ID</label>
                <input 
                  type="text" 
                  className="w-full bg-surface border border-borderSubtle rounded-md px-4 py-2 text-textMain focus:outline-none focus:ring-2 focus:ring-primary/50 transition-all"
                  placeholder="admin"
                />
              </div>
              <div className="space-y-2">
                <label className="text-sm font-medium text-textMuted">Passkey</label>
                <input 
                  type="password" 
                  className="w-full bg-surface border border-borderSubtle rounded-md px-4 py-2 text-textMain focus:outline-none focus:ring-2 focus:ring-primary/50 transition-all"
                  placeholder="••••••••"
                />
              </div>
              
              <Button type="submit" className="w-full mt-4 group">
                <Lock className="w-4 h-4 mr-2 group-hover:text-white transition-colors" />
                Initialize Session
              </Button>
            </form>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
