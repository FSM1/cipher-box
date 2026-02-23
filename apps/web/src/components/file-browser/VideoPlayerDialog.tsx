import { useState, useEffect, useRef, useCallback } from 'react';
import type { FilePointer } from '@cipherbox/crypto';
import { Modal } from '../ui/Modal';
import { useFilePreview } from '../../hooks/useFilePreview';
import { useStreamingPreview } from '../../hooks/useStreamingPreview';
import '../../styles/video-player-dialog.css';

type VideoPlayerDialogProps = {
  open: boolean;
  onClose: () => void;
  item: FilePointer | null;
  /** Parent folder's decrypted AES-256 key (needed to decrypt file metadata) */
  folderKey: Uint8Array | null;
  /** Share ID when previewing from a shared folder — uses re-wrapped file keys */
  shareId?: string | null;
};

/** Map common video extensions to MIME types. */
const VIDEO_MIME: Record<string, string> = {
  '.mp4': 'video/mp4',
  '.webm': 'video/webm',
  '.mov': 'video/mp4',
  '.mkv': 'video/x-matroska',
};

/** MIME types eligible for CTR streaming playback. */
const STREAMING_VIDEO_MIMES = new Set(['video/mp4', 'video/webm']);

function getVideoMime(filename: string): string {
  const lower = filename.toLowerCase();
  const lastDot = lower.lastIndexOf('.');
  if (lastDot === -1) return 'video/mp4';
  return VIDEO_MIME[lower.slice(lastDot)] ?? 'video/mp4';
}

function formatTime(seconds: number): string {
  if (!isFinite(seconds) || seconds < 0) return '00:00';
  const m = Math.floor(seconds / 60);
  const s = Math.floor(seconds % 60);
  return `${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
}

const SPEED_OPTIONS = [1, 1.5, 2, 0.5] as const;

/**
 * Modal dialog for playing video files with custom overlay controls.
 *
 * Supports both CTR streaming (via Service Worker) and GCM blob URL playback.
 * No native browser video controls -- fully custom UI with play/pause,
 * seek, volume, speed, and fullscreen. Controls auto-hide during playback.
 */
export function VideoPlayerDialog({
  open,
  onClose,
  item,
  folderKey,
  shareId,
}: VideoPlayerDialogProps) {
  const mimeType = item ? getVideoMime(item.name) : 'video/mp4';
  const isStreamingCandidate = item ? STREAMING_VIDEO_MIMES.has(getVideoMime(item.name)) : false;

  // Streaming preview (CTR via Service Worker)
  const streaming = useStreamingPreview({
    open: open && isStreamingCandidate,
    item,
    mimeType,
    folderKey,
  });

  // Blob URL preview (GCM fallback or when SW not ready)
  // Gate on !streaming.loading to avoid redundant blob fetch while CTR check resolves
  const blobPreview = useFilePreview({
    open:
      open &&
      (!isStreamingCandidate || !streaming.isSwReady || (!streaming.loading && !streaming.isCtr)),
    item,
    mimeType,
    folderKey,
    shareId,
  });

  // Determine active preview mode
  const isStreaming =
    isStreamingCandidate && streaming.isSwReady && streaming.isCtr && !streaming.error;
  const videoSrc = isStreaming ? streaming.streamUrl : blobPreview.objectUrl;
  const isLoading = isStreaming ? streaming.loading : blobPreview.loading;
  const previewError = isStreaming ? streaming.error : blobPreview.error;
  const onDownload = isStreaming ? streaming.handleDownload : blobPreview.handleDownload;

  // Video state
  const [isPlaying, setIsPlaying] = useState(false);
  const [currentTime, setCurrentTime] = useState(0);
  const [duration, setDuration] = useState(0);
  const [volume, setVolume] = useState(0.7);
  const [speedIndex, setSpeedIndex] = useState(0); // index into SPEED_OPTIONS
  const [videoWidth, setVideoWidth] = useState(0);
  const [videoHeight, setVideoHeight] = useState(0);
  const [controlsVisible, setControlsVisible] = useState(true);
  const [bufferedPercent, setBufferedPercent] = useState(0);

  // Refs
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const progressRef = useRef<HTMLDivElement | null>(null);
  const hideTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Reset state when dialog closes
  useEffect(() => {
    if (!open) {
      setIsPlaying(false);
      setCurrentTime(0);
      setDuration(0);
      setSpeedIndex(0);
      setVideoWidth(0);
      setVideoHeight(0);
      setControlsVisible(true);
      setBufferedPercent(0);
      if (hideTimerRef.current) {
        clearTimeout(hideTimerRef.current);
        hideTimerRef.current = null;
      }
      if (clickTimerRef.current) {
        clearTimeout(clickTimerRef.current);
        clickTimerRef.current = null;
      }
    }
  }, [open]);

  // Sync volume and speed to video element
  useEffect(() => {
    if (videoRef.current) {
      videoRef.current.volume = volume;
    }
  }, [volume]);

  useEffect(() => {
    if (videoRef.current) {
      videoRef.current.playbackRate = SPEED_OPTIONS[speedIndex];
    }
  }, [speedIndex]);

  // Auto-hide controls during playback
  const resetHideTimer = useCallback(() => {
    if (hideTimerRef.current) {
      clearTimeout(hideTimerRef.current);
    }
    setControlsVisible(true);

    hideTimerRef.current = setTimeout(() => {
      if (videoRef.current && !videoRef.current.paused) {
        setControlsVisible(false);
      }
    }, 3000);
  }, []);

  useEffect(() => {
    if (isPlaying) {
      resetHideTimer();
    } else {
      if (hideTimerRef.current) {
        clearTimeout(hideTimerRef.current);
      }
      setControlsVisible(true);
    }
  }, [isPlaying, resetHideTimer]);

  // Video event handlers
  const handleTimeUpdate = useCallback(() => {
    const video = videoRef.current;
    if (!video) return;
    setCurrentTime(video.currentTime);

    // Update buffered percentage
    if (video.buffered.length > 0) {
      const buffered = video.buffered.end(video.buffered.length - 1);
      setBufferedPercent(video.duration > 0 ? (buffered / video.duration) * 100 : 0);
    }
  }, []);

  const handleLoadedMetadata = useCallback(() => {
    const video = videoRef.current;
    if (!video) return;
    setDuration(video.duration);
    setVideoWidth(video.videoWidth);
    setVideoHeight(video.videoHeight);
    video.volume = volume;
    video.playbackRate = SPEED_OPTIONS[speedIndex];
  }, [volume, speedIndex]);

  const handleEnded = useCallback(() => {
    setIsPlaying(false);
  }, []);

  const handlePlay = useCallback(() => {
    setIsPlaying(true);
  }, []);

  const handlePause = useCallback(() => {
    setIsPlaying(false);
  }, []);

  // Transport controls
  const togglePlayPause = useCallback(async () => {
    const video = videoRef.current;
    if (!video) return;

    if (video.paused) {
      try {
        await video.play();
      } catch {
        // Browser blocked playback (autoplay policy / interruption)
      }
    } else {
      video.pause();
    }
  }, []);

  const clickTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const handleVideoClick = useCallback(() => {
    // Delay single-click to distinguish from double-click
    if (clickTimerRef.current) {
      clearTimeout(clickTimerRef.current);
      clickTimerRef.current = null;
      return; // Second click of a double-click; handled by handleVideoDoubleClick
    }
    clickTimerRef.current = setTimeout(() => {
      clickTimerRef.current = null;
      togglePlayPause();
      resetHideTimer();
    }, 250);
  }, [togglePlayPause, resetHideTimer]);

  const handleVideoDoubleClick = useCallback(() => {
    if (clickTimerRef.current) {
      clearTimeout(clickTimerRef.current);
      clickTimerRef.current = null;
    }

    const container = containerRef.current;
    if (!container) return;

    if (document.fullscreenElement) {
      document.exitFullscreen();
    } else if ('webkitRequestFullscreen' in container) {
      (
        container as HTMLDivElement & { webkitRequestFullscreen: () => void }
      ).webkitRequestFullscreen();
    } else {
      container.requestFullscreen();
    }
  }, []);

  const handleMouseMove = useCallback(() => {
    resetHideTimer();
  }, [resetHideTimer]);

  // Seek via progress bar click
  const handleProgressClick = useCallback(
    (e: React.MouseEvent<HTMLDivElement>) => {
      const video = videoRef.current;
      if (!video || !progressRef.current || !duration) return;

      const rect = progressRef.current.getBoundingClientRect();
      const ratio = Math.max(0, Math.min(1, (e.clientX - rect.left) / rect.width));
      video.currentTime = ratio * duration;
    },
    [duration]
  );

  const handleVolumeChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    setVolume(parseFloat(e.target.value));
  }, []);

  const handleSpeedCycle = useCallback(() => {
    setSpeedIndex((i) => (i + 1) % SPEED_OPTIONS.length);
  }, []);

  const handleFullscreen = useCallback(() => {
    const container = containerRef.current;
    if (!container) return;

    if (document.fullscreenElement) {
      document.exitFullscreen();
    } else if ('webkitRequestFullscreen' in container) {
      (
        container as HTMLDivElement & { webkitRequestFullscreen: () => void }
      ).webkitRequestFullscreen();
    } else {
      container.requestFullscreen();
    }
  }, []);

  const streamingCleanup = streaming.cleanup;
  const handleClose = useCallback(() => {
    if (videoRef.current) {
      videoRef.current.pause();
    }
    setIsPlaying(false);
    streamingCleanup();
    onClose();
  }, [onClose, streamingCleanup]);

  if (!item) return null;

  const progressPercent = duration > 0 ? (currentTime / duration) * 100 : 0;
  const currentSpeed = SPEED_OPTIONS[speedIndex];
  const showPlayOverlay = !isPlaying;

  // Show decrypt progress bar during streaming fetch
  const showDecryptProgress =
    isStreaming && streaming.decryptProgress > 0 && streaming.decryptProgress < 100;

  return (
    <Modal open={open} onClose={handleClose} className="video-player-modal">
      {isLoading || showDecryptProgress ? (
        <div className="video-preview-loading">
          {isStreaming && streaming.decryptProgress > 0 ? (
            <>
              <div className="video-decrypt-label">decrypting...</div>
              <div className="video-decrypt-progress-track">
                <div
                  className="video-decrypt-progress-fill"
                  style={{ width: `${streaming.decryptProgress}%` }}
                />
              </div>
              <div className="video-decrypt-percent">{Math.round(streaming.decryptProgress)}%</div>
            </>
          ) : (
            'decrypting...'
          )}
        </div>
      ) : previewError ? (
        <div className="video-preview-error">
          {'> '}
          {previewError}
        </div>
      ) : (
        <>
          {/* Toolbar */}
          <div className="video-toolbar">
            <div className="video-toolbar-left">
              <span className="video-tag">VID</span>
              <span className="video-filename">{item.name}</span>
            </div>
            <div className="video-toolbar-right">
              <button
                type="button"
                className="video-btn"
                onClick={onDownload}
                aria-label="Download file"
              >
                [download]
              </button>
            </div>
          </div>

          {/* Video screen */}
          <div className="video-screen" ref={containerRef} onMouseMove={handleMouseMove}>
            {videoSrc && (
              <video
                ref={videoRef}
                src={videoSrc}
                onTimeUpdate={handleTimeUpdate}
                onLoadedMetadata={handleLoadedMetadata}
                onEnded={handleEnded}
                onPlay={handlePlay}
                onPause={handlePause}
                onClick={handleVideoClick}
                onDoubleClick={handleVideoDoubleClick}
              />
            )}

            {/* Play overlay */}
            {showPlayOverlay && (
              <div
                className="video-play-overlay"
                onClick={handleVideoClick}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    togglePlayPause();
                  }
                }}
                role="button"
                aria-label="Play video"
                tabIndex={0}
              >
                <span className="video-play-icon">{'\u25B6'}</span>
              </div>
            )}

            {/* Resolution badge */}
            {videoWidth > 0 && videoHeight > 0 && (
              <span className="video-resolution">
                {videoWidth}x{videoHeight}
              </span>
            )}

            {/* Encrypted streaming badge */}
            {isStreaming && <span className="video-cipher-badge">ENCRYPTED</span>}
          </div>

          {/* Controls bar */}
          <div
            className={`video-controls-bar${!controlsVisible ? ' video-controls-bar--hidden' : ''}`}
          >
            {/* Progress bar */}
            <div
              className="video-progress-track"
              ref={progressRef}
              onClick={handleProgressClick}
              onKeyDown={(e) => {
                const video = videoRef.current;
                if (!video || !duration) return;
                const step = e.shiftKey ? 10 : 5;
                if (e.key === 'ArrowRight') {
                  e.preventDefault();
                  video.currentTime = Math.min(duration, video.currentTime + step);
                } else if (e.key === 'ArrowLeft') {
                  e.preventDefault();
                  video.currentTime = Math.max(0, video.currentTime - step);
                }
              }}
              role="slider"
              aria-label="Video progress"
              aria-valuemin={0}
              aria-valuemax={Math.floor(duration)}
              aria-valuenow={Math.floor(currentTime)}
              tabIndex={0}
            >
              <div className="video-progress-buffered" style={{ width: `${bufferedPercent}%` }} />
              <div className="video-progress-fill" style={{ width: `${progressPercent}%` }} />
            </div>

            {/* Control row */}
            <div className="video-control-row">
              <div className="video-control-left">
                <button
                  type="button"
                  className="video-btn"
                  onClick={togglePlayPause}
                  aria-label={isPlaying ? 'Pause' : 'Play'}
                >
                  {isPlaying ? '[||]' : '[>]'}
                </button>
                <span className="video-time-display">
                  {formatTime(currentTime)} / {formatTime(duration)}
                </span>
              </div>
              <div className="video-control-right">
                <div className="video-volume-wrapper">
                  <span className="video-volume-label">vol:</span>
                  <input
                    type="range"
                    className="video-volume-slider"
                    min="0"
                    max="1"
                    step="0.01"
                    value={volume}
                    onChange={handleVolumeChange}
                    aria-label="Volume"
                  />
                </div>
                <button
                  type="button"
                  className="video-btn"
                  onClick={handleSpeedCycle}
                  aria-label="Playback speed"
                >
                  [{currentSpeed}x]
                </button>
                <button
                  type="button"
                  className="video-btn"
                  onClick={handleFullscreen}
                  aria-label="Toggle fullscreen"
                >
                  [full]
                </button>
              </div>
            </div>
          </div>
        </>
      )}
    </Modal>
  );
}
