import { useState, useEffect, useRef, useCallback } from 'react';
import type { FileEntry } from '@cipherbox/crypto';
import { Modal } from '../ui/Modal';
import { useFilePreview } from '../../hooks/useFilePreview';
import '../../styles/video-player-dialog.css';

type VideoPlayerDialogProps = {
  open: boolean;
  onClose: () => void;
  item: FileEntry | null;
};

/** Map common video extensions to MIME types. */
const VIDEO_MIME: Record<string, string> = {
  '.mp4': 'video/mp4',
  '.webm': 'video/webm',
  '.mov': 'video/mp4',
  '.mkv': 'video/x-matroska',
};

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
 * No native browser video controls -- fully custom UI with play/pause,
 * seek, volume, speed, and fullscreen. Controls auto-hide during playback.
 */
export function VideoPlayerDialog({ open, onClose, item }: VideoPlayerDialogProps) {
  const mimeType = item ? getVideoMime(item.name) : 'video/mp4';
  const { loading, error, objectUrl, handleDownload } = useFilePreview({
    open,
    item,
    mimeType,
  });

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
  }, []);

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

  const handleClose = useCallback(() => {
    if (videoRef.current) {
      videoRef.current.pause();
    }
    setIsPlaying(false);
    onClose();
  }, [onClose]);

  if (!item) return null;

  const progressPercent = duration > 0 ? (currentTime / duration) * 100 : 0;
  const currentSpeed = SPEED_OPTIONS[speedIndex];
  const showPlayOverlay = !isPlaying;

  return (
    <Modal open={open} onClose={handleClose} className="video-player-modal">
      {loading ? (
        <div className="video-preview-loading">decrypting...</div>
      ) : error ? (
        <div className="video-preview-error">
          {'> '}
          {error}
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
                onClick={handleDownload}
                aria-label="Download file"
              >
                [download]
              </button>
            </div>
          </div>

          {/* Video screen */}
          <div className="video-screen" ref={containerRef} onMouseMove={handleMouseMove}>
            {objectUrl && (
              <video
                ref={videoRef}
                src={objectUrl}
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
