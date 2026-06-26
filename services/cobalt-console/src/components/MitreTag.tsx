'use client';

import { useState } from 'react';
import type { MitreTechnique } from '@/lib/types';

interface MitreTagProps {
  technique: MitreTechnique;
}

export default function MitreTag({ technique }: MitreTagProps) {
  const [showTooltip, setShowTooltip] = useState(false);

  return (
    <div className="relative inline-block">
      <button
        onMouseEnter={() => setShowTooltip(true)}
        onMouseLeave={() => setShowTooltip(false)}
        className="inline-flex items-center gap-1 rounded bg-cobalt-500/20 px-2 py-0.5 text-xs font-mono text-cobalt-300 hover:bg-cobalt-500/30 transition-colors"
      >
        {technique.id}
      </button>
      {showTooltip && (
        <div className="absolute z-50 bottom-full left-1/2 -translate-x-1/2 mb-2 w-64 rounded-lg border border-dark-700 bg-dark-800 p-3 shadow-xl">
          <div className="text-sm font-semibold text-white">{technique.name}</div>
          <div className="mt-1 text-xs text-gray-400">{technique.id}</div>
          <div className="mt-1 text-xs text-gray-500">Tactic: {technique.tactic}</div>
          <div className="mt-1 text-xs">
            <span className="text-gray-500">Confidence: </span>
            <span className={technique.confidence > 0.7 ? 'text-green-400' : 'text-yellow-400'}>
              {(technique.confidence * 100).toFixed(0)}%
            </span>
          </div>
          <div className="absolute -bottom-1 left-1/2 -translate-x-1/2 h-2 w-2 rotate-45 bg-dark-800 border-r border-b border-dark-700" />
        </div>
      )}
    </div>
  );
}
