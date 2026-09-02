import React from 'react';
import { Shield, Bell, User } from 'lucide-react';

export function Navbar() {
  return (
    <nav className="h-16 border-b border-borderSubtle bg-background/80 backdrop-blur-md flex items-center justify-between px-6 sticky top-0 z-50">
      <div className="flex items-center gap-3">
        <Shield className="w-8 h-8 text-primary" />
        <span className="text-xl font-bold tracking-wider neon-text-primary">GARUD-AI</span>
      </div>
      
      <div className="flex items-center gap-4">
        <button className="p-2 rounded-full hover:bg-surfaceHighlight transition-colors text-textMuted hover:text-textMain">
          <Bell className="w-5 h-5" />
        </button>
        <button className="flex items-center gap-2 p-1.5 rounded-full hover:bg-surfaceHighlight transition-colors border border-borderSubtle px-3">
          <User className="w-4 h-4 text-primary" />
          <span className="text-sm font-medium">Analyst</span>
        </button>
      </div>
    </nav>
  );
}
