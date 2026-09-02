import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard, UploadCloud, Database, Settings,
  Shield, Target, FileText, Activity, Network
} from 'lucide-react';
import { cn } from '../../utils/cn';

const navItems = [
  { icon: LayoutDashboard, label: 'Dashboard',       path: '/dashboard' },
  { icon: UploadCloud,     label: 'Analyze APK',     path: '/upload' },
  { icon: Activity,        label: 'Investigations',  path: '/investigations' },
  { icon: Database,        label: 'Threat Memory',   path: '/threats' },
  { icon: Target,          label: 'IOC Search',      path: '/ioc-search' },
  { icon: FileText,        label: 'Reports',         path: '/reports' },
  { icon: Settings,        label: 'Settings',        path: '/settings' },
];

export function Sidebar() {
  return (
    <aside className="w-60 border-r border-borderSubtle bg-surface/50 hidden md:flex flex-col h-[calc(100vh-4rem)] sticky top-16">
      {/* Logo bar */}
      <div className="px-4 py-4 border-b border-borderSubtle">
        <div className="flex items-center gap-2">
          <Shield className="w-5 h-5 text-primary" />
          <div>
            <p className="text-xs font-bold text-primary tracking-widest">GARUD-AI</p>
            <p className="text-[10px] text-textMuted tracking-wide">CyberShield Platform</p>
          </div>
        </div>
      </div>

      {/* Nav */}
      <div className="p-3 flex-1 overflow-y-auto">
        <p className="text-[10px] uppercase text-textMuted font-semibold px-3 mb-2 tracking-widest">Navigation</p>
        <ul className="space-y-1">
          {navItems.map((item) => (
            <li key={item.path}>
              <NavLink
                to={item.path}
                className={({ isActive }) => cn(
                  "flex items-center gap-3 px-3 py-2.5 rounded-lg transition-all duration-200 text-sm",
                  isActive
                    ? "bg-primary/10 text-primary font-semibold border border-primary/20"
                    : "text-textMuted hover:bg-surfaceHighlight hover:text-textMain"
                )}
              >
                <item.icon className="w-4 h-4" />
                {item.label}
              </NavLink>
            </li>
          ))}
        </ul>
      </div>

      {/* System status footer */}
      <div className="p-3 border-t border-borderSubtle space-y-2">
        <div className="bg-surfaceHighlight/50 rounded-lg p-3 border border-borderSubtle">
          <p className="text-[10px] text-textMuted uppercase tracking-widest mb-2">System Status</p>
          <div className="space-y-1.5">
            {["Pipeline Engine", "AI Agents (8)", "Threat Memory"].map(s => (
              <div key={s} className="flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-success animate-pulse" />
                <span className="text-xs text-textMuted">{s}</span>
              </div>
            ))}
          </div>
        </div>
        <div className="text-center">
          <p className="text-[10px] text-textMuted opacity-50">GARUD-AI v1.0 • Bank of India</p>
        </div>
      </div>
    </aside>
  );
}
