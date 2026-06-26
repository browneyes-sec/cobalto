'use client';

import { useState } from 'react';
import { Dialog, DialogPanel, DialogTitle, DialogBackdrop } from '@headlessui/react';
import type { ResponseAction } from '@/lib/types';

interface ApprovalDialogProps {
  action: ResponseAction;
  isOpen: boolean;
  onClose: () => void;
  onApprove: (actionId: string, notes: string) => void;
  onReject: (actionId: string, notes: string) => void;
}

export default function ApprovalDialog({
  action,
  isOpen,
  onClose,
  onApprove,
  onReject,
}: ApprovalDialogProps) {
  const [notes, setNotes] = useState('');

  const handleApprove = () => {
    onApprove(action.id, notes);
    setNotes('');
    onClose();
  };

  const handleReject = () => {
    onReject(action.id, notes);
    setNotes('');
    onClose();
  };

  return (
    <Dialog open={isOpen} onClose={onClose} className="relative z-50">
      <DialogBackdrop className="fixed inset-0 bg-black/60" />
      <div className="fixed inset-0 overflow-y-auto">
        <div className="flex min-h-full items-center justify-center p-4">
          <DialogPanel className="w-full max-w-lg rounded-xl border border-dark-700 bg-dark-800 p-6 shadow-2xl">
            <DialogTitle className="text-lg font-semibold text-white">
              Review Response Action
            </DialogTitle>

            <div className="mt-4 space-y-3">
              <div className="rounded-lg bg-dark-900 p-4">
                <div className="text-sm font-medium text-gray-300">Action Type</div>
                <div className="mt-1 text-sm text-white">{action.type}</div>
              </div>
              <div className="rounded-lg bg-dark-900 p-4">
                <div className="text-sm font-medium text-gray-300">Description</div>
                <div className="mt-1 text-sm text-white">{action.description}</div>
              </div>
              <div className="rounded-lg bg-dark-900 p-4">
                <div className="text-sm font-medium text-gray-300">Requested By</div>
                <div className="mt-1 text-sm text-white">{action.requestedBy}</div>
              </div>
            </div>

            <div className="mt-4">
              <label className="block text-sm font-medium text-gray-300">
                Approval Notes
              </label>
              <textarea
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                rows={3}
                className="mt-1 w-full rounded-lg border border-dark-700 bg-dark-900 px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-cobalt-500 focus:outline-none focus:ring-1 focus:ring-cobalt-500"
                placeholder="Add notes for audit trail..."
              />
            </div>

            <div className="mt-6 flex justify-end gap-3">
              <button
                onClick={handleReject}
                className="rounded-lg bg-red-500/20 px-4 py-2 text-sm font-medium text-red-400 hover:bg-red-500/30 transition-colors"
              >
                Reject
              </button>
              <button
                onClick={handleApprove}
                className="rounded-lg bg-green-500/20 px-4 py-2 text-sm font-medium text-green-400 hover:bg-green-500/30 transition-colors"
              >
                Approve
              </button>
              <button
                onClick={onClose}
                className="rounded-lg border border-dark-700 px-4 py-2 text-sm font-medium text-gray-400 hover:bg-dark-700 transition-colors"
              >
                Cancel
              </button>
            </div>
          </DialogPanel>
        </div>
      </div>
    </Dialog>
  );
}
