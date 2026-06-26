'use client';

import type { Severity } from '@/lib/types';

const severityConfig: Record<Severity, { bg: string; text: string; dot: string }> = {
  CRITICAL: { bg: 'bg-red-500/20', text: 'text-red-400', dot: 'bg-red-500' },
  HIGH: { bg: 'bg-orange-500/20', text: 'text-orange-400', dot: 'bg-orange-500' },
  MEDIUM: { bg: 'bg-yellow-500/20', text: 'text-yellow-400', dot: 'bg-yellow-500' },
  LOW: { bg: 'bg-blue-500/20', text: 'text-blue-400', dot: 'bg-blue-500' },
};

interface SeverityBadgeProps {
  severity: Severity;
  size?: 'sm' | 'md' | 'lg';
}

export default function SeverityBadge({ severity, size = 'md' }: SeverityBadgeProps) {
  const config = severityConfig[severity];
  const sizeClasses = {
    sm: 'px-1.5 py-0.5 text-xs',
    md: 'px-2 py-1 text-sm',
    lg: 'px-3 py-1.5 text-base',
  };

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full font-medium ${config.bg} ${config.text} ${sizeClasses[size]}`}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${config.dot}`} />
      {severity}
    </span>
  );
}
