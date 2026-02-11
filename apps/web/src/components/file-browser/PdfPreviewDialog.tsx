import { useState, useEffect, useRef, useCallback } from 'react';
import type { FileEntry } from '@cipherbox/crypto';
import * as pdfjsLib from 'pdfjs-dist';
import type { PDFDocumentProxy } from 'pdfjs-dist';
import { Modal } from '../ui/Modal';
import { useFilePreview } from '../../hooks/useFilePreview';
import '../../styles/pdf-preview-dialog.css';

// Configure PDF.js worker
pdfjsLib.GlobalWorkerOptions.workerSrc = new URL(
  'pdfjs-dist/build/pdf.worker.min.mjs',
  import.meta.url
).href;

type PdfPreviewDialogProps = {
  open: boolean;
  onClose: () => void;
  item: FileEntry | null;
};

const MIN_ZOOM = 0.25;
const MAX_ZOOM = 4.0;
const ZOOM_STEP = 0.25;

/**
 * Modal dialog for previewing PDF files in-browser.
 *
 * Downloads the encrypted file from IPFS, decrypts it, and renders
 * all pages using pdfjs-dist canvases. Supports zoom and page navigation.
 */
export function PdfPreviewDialog({ open, onClose, item }: PdfPreviewDialogProps) {
  const { loading, error, objectUrl, handleDownload } = useFilePreview({
    open,
    item,
    mimeType: 'application/pdf',
  });

  const [zoom, setZoom] = useState(1.0);
  const [numPages, setNumPages] = useState(0);
  const [currentPage, setCurrentPage] = useState(1);
  const [pdfLoading, setPdfLoading] = useState(false);

  const pdfDocRef = useRef<PDFDocumentProxy | null>(null);
  const canvasRefsMap = useRef<Map<number, HTMLCanvasElement>>(new Map());
  const canvasAreaRef = useRef<HTMLDivElement | null>(null);
  const observerRef = useRef<IntersectionObserver | null>(null);
  const renderingRef = useRef(false);

  // Load the PDF document when objectUrl is available
  useEffect(() => {
    if (!objectUrl) {
      // Reset state when closing
      if (pdfDocRef.current) {
        pdfDocRef.current.destroy();
        pdfDocRef.current = null;
      }
      canvasRefsMap.current.clear();
      setNumPages(0);
      setCurrentPage(1);
      setZoom(1.0);
      setPdfLoading(false);
      return;
    }

    let cancelled = false;
    setPdfLoading(true);

    (async () => {
      try {
        const doc = await pdfjsLib.getDocument(objectUrl).promise;
        if (cancelled) {
          doc.destroy();
          return;
        }
        pdfDocRef.current = doc;
        setNumPages(doc.numPages);
        setPdfLoading(false);
      } catch (err) {
        if (cancelled) return;
        console.error('Failed to load PDF:', err);
        setPdfLoading(false);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [objectUrl]);

  // Render all pages when numPages or zoom changes
  useEffect(() => {
    const doc = pdfDocRef.current;
    if (!doc || numPages === 0 || renderingRef.current) return;

    renderingRef.current = true;

    (async () => {
      try {
        for (let i = 1; i <= numPages; i++) {
          const canvas = canvasRefsMap.current.get(i);
          if (!canvas) continue;

          const page = await doc.getPage(i);
          const viewport = page.getViewport({ scale: zoom });
          canvas.width = viewport.width;
          canvas.height = viewport.height;

          await page.render({ canvas, viewport }).promise;
        }
      } catch (err) {
        console.error('Failed to render PDF pages:', err);
      } finally {
        renderingRef.current = false;
      }
    })();
  }, [numPages, zoom]);

  // IntersectionObserver to track current visible page
  useEffect(() => {
    if (!canvasAreaRef.current || numPages === 0) return;

    observerRef.current = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (entry.isIntersecting) {
            const pageNum = Number(entry.target.getAttribute('data-page'));
            if (pageNum && !isNaN(pageNum)) {
              setCurrentPage(pageNum);
            }
          }
        }
      },
      {
        root: canvasAreaRef.current,
        threshold: 0.5,
      }
    );

    canvasRefsMap.current.forEach((canvas) => {
      observerRef.current?.observe(canvas);
    });

    return () => {
      observerRef.current?.disconnect();
    };
  }, [numPages, zoom]);

  // Store canvas ref for a given page
  const setCanvasRef = useCallback((pageNum: number, el: HTMLCanvasElement | null) => {
    if (el) {
      canvasRefsMap.current.set(pageNum, el);
    } else {
      canvasRefsMap.current.delete(pageNum);
    }
  }, []);

  // Zoom controls
  const handleZoomIn = useCallback(() => {
    setZoom((z) => Math.min(z + ZOOM_STEP, MAX_ZOOM));
  }, []);

  const handleZoomOut = useCallback(() => {
    setZoom((z) => Math.max(z - ZOOM_STEP, MIN_ZOOM));
  }, []);

  const handleFit = useCallback(() => {
    if (!canvasAreaRef.current || !pdfDocRef.current) return;

    (async () => {
      try {
        const page = await pdfDocRef.current!.getPage(1);
        const viewport = page.getViewport({ scale: 1.0 });
        const containerWidth = canvasAreaRef.current!.clientWidth - 32; // subtract padding
        const fitScale = containerWidth / viewport.width;
        setZoom(Math.max(MIN_ZOOM, Math.min(fitScale, MAX_ZOOM)));
      } catch {
        // fallback
        setZoom(1.0);
      }
    })();
  }, []);

  // Page navigation
  const handlePrevPage = useCallback(() => {
    const target = Math.max(1, currentPage - 1);
    const canvas = canvasRefsMap.current.get(target);
    if (canvas) {
      canvas.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  }, [currentPage]);

  const handleNextPage = useCallback(() => {
    const target = Math.min(numPages, currentPage + 1);
    const canvas = canvasRefsMap.current.get(target);
    if (canvas) {
      canvas.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  }, [currentPage, numPages]);

  if (!item) return null;

  const zoomPercent = Math.round(zoom * 100);
  const isContentLoading = loading || pdfLoading;

  return (
    <Modal open={open} onClose={onClose} className="pdf-preview-modal">
      {isContentLoading ? (
        <div className="pdf-preview-loading">decrypting...</div>
      ) : error ? (
        <div className="pdf-preview-error">
          {'> '}
          {error}
        </div>
      ) : (
        <>
          {/* Toolbar */}
          <div className="pdf-toolbar">
            <div className="pdf-toolbar-left">
              <span className="pdf-tag">PDF</span>
              <span className="pdf-filename">{item.name}</span>
            </div>
            <div className="pdf-toolbar-right">
              <button
                type="button"
                className="pdf-btn"
                onClick={handleZoomOut}
                disabled={zoom <= MIN_ZOOM}
                aria-label="Zoom out"
              >
                [-]
              </button>
              <span className="pdf-zoom-display">{zoomPercent}%</span>
              <button
                type="button"
                className="pdf-btn"
                onClick={handleZoomIn}
                disabled={zoom >= MAX_ZOOM}
                aria-label="Zoom in"
              >
                [+]
              </button>
              <button
                type="button"
                className="pdf-btn"
                onClick={handleFit}
                aria-label="Fit to width"
              >
                [fit]
              </button>
              <button
                type="button"
                className="pdf-btn"
                onClick={handleDownload}
                aria-label="Download file"
              >
                [download]
              </button>
            </div>
          </div>

          {/* Canvas area */}
          <div className="pdf-canvas-area" ref={canvasAreaRef}>
            {Array.from({ length: numPages }, (_, i) => i + 1).map((pageNum) => (
              <canvas key={pageNum} ref={(el) => setCanvasRef(pageNum, el)} data-page={pageNum} />
            ))}
          </div>

          {/* Footer */}
          <div className="pdf-footer">
            <button
              type="button"
              className="pdf-btn"
              onClick={handlePrevPage}
              disabled={currentPage <= 1}
              aria-label="Previous page"
            >
              [&lt;&lt;]
            </button>
            <span className="pdf-page-info">
              page {currentPage} / {numPages}
            </span>
            <button
              type="button"
              className="pdf-btn"
              onClick={handleNextPage}
              disabled={currentPage >= numPages}
              aria-label="Next page"
            >
              [&gt;&gt;]
            </button>
          </div>
        </>
      )}
    </Modal>
  );
}
