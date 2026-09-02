import React from 'react';
import { cn } from '../../utils/cn';

const Badge = React.forwardRef(({ className, variant = 'default', ...props }, ref) => {
  const baseStyles = "inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2";
  
  const variants = {
    default: "border-transparent bg-primary text-white",
    secondary: "border-transparent bg-surfaceHighlight text-textMain",
    danger: "border-transparent bg-danger/20 text-danger",
    warning: "border-transparent bg-warning/20 text-warning",
    success: "border-transparent bg-success/20 text-success",
    outline: "text-textMain border-borderSubtle",
  };

  return (
    <div
      ref={ref}
      className={cn(baseStyles, variants[variant], className)}
      {...props}
    />
  );
});

Badge.displayName = "Badge";

export { Badge };
