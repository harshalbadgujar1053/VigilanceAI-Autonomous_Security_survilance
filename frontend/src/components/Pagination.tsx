import React from 'react';
import { ChevronLeft, ChevronRight } from 'lucide-react';

interface PaginationProps {
  currentPage: number;       // 1-indexed
  totalItems: number;
  pageSize: number;
  onPageChange: (page: number) => void;
}

const Pagination: React.FC<PaginationProps> = ({ currentPage, totalItems, pageSize, onPageChange }) => {
  const totalPages = Math.max(1, Math.ceil(totalItems / pageSize));

  if (totalPages <= 1) return null;

  // Build a compact page list: always show first, last, current, and
  // one neighbor on each side; collapse the rest into '...'
  const pages: (number | 'ellipsis')[] = [];
  for (let p = 1; p <= totalPages; p++) {
    if (p === 1 || p === totalPages || Math.abs(p - currentPage) <= 1) {
      pages.push(p);
    } else if (pages[pages.length - 1] !== 'ellipsis') {
      pages.push('ellipsis');
    }
  }

  return (
    <div
      className="pagination-bar"
      style={{
        display: 'flex',
        justifyContent: 'flex-end',
        alignItems: 'center',
        gap: '6px',
        marginTop: '16px',
        padding: '8px 4px'
      }}
    >
      <span style={{ fontSize: '12px', color: 'var(--color-text-secondary, #64748B)', marginRight: '8px' }}>
        Rows per page: {pageSize}
      </span>

      <button
        onClick={() => onPageChange(Math.max(1, currentPage - 1))}
        disabled={currentPage === 1}
        aria-label="Previous page"
        className="pagination-btn"
        style={{
          width: '30px',
          height: '30px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          borderRadius: '6px',
          border: '1px solid #E2E8F0',
          background: '#FFFFFF',
          cursor: currentPage === 1 ? 'not-allowed' : 'pointer',
          opacity: currentPage === 1 ? 0.4 : 1
        }}
      >
        <ChevronLeft size={15} />
      </button>

      {pages.map((p, idx) =>
        p === 'ellipsis' ? (
          <span key={`ellipsis-${idx}`} style={{ padding: '0 4px', color: 'var(--color-text-secondary, #64748B)', fontSize: '13px' }}>
            …
          </span>
        ) : (
          <button
            key={p}
            onClick={() => onPageChange(p)}
            aria-current={p === currentPage ? 'page' : undefined}
            className="pagination-btn"
            style={{
              minWidth: '30px',
              height: '30px',
              padding: '0 8px',
              borderRadius: '6px',
              border: '1px solid #E2E8F0',
              background: p === currentPage ? '#F0FDFA' : '#FFFFFF',
              color: p === currentPage ? '#0F766E' : 'var(--color-text-primary, #1E293B)',
              fontWeight: p === currentPage ? 700 : 500,
              fontSize: '13px',
              cursor: 'pointer'
            }}
          >
            {p}
          </button>
        )
      )}

      <button
        onClick={() => onPageChange(Math.min(totalPages, currentPage + 1))}
        disabled={currentPage === totalPages}
        aria-label="Next page"
        className="pagination-btn"
        style={{
          width: '30px',
          height: '30px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          borderRadius: '6px',
          border: '1px solid #E2E8F0',
          background: '#FFFFFF',
          cursor: currentPage === totalPages ? 'not-allowed' : 'pointer',
          opacity: currentPage === totalPages ? 0.4 : 1
        }}
      >
        <ChevronRight size={15} />
      </button>
    </div>
  );
};

export default Pagination;
