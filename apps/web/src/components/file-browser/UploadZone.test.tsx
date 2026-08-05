import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { UploadZone } from './UploadZone';

const dropped = (files: File[]) => ({
  dataTransfer: { files, types: ['Files'], dropEffect: 'none' },
});

describe('the upload drop zone', () => {
  it('hands dropped files to its caller', () => {
    const onFiles = vi.fn();
    render(<UploadZone onFiles={onFiles} busy={false} />);
    const zone = screen.getByTestId('upload-zone');
    const file = new File(['x'], 'notes.txt');

    fireEvent.drop(zone, dropped([file]));

    expect(onFiles).toHaveBeenCalledWith([file]);
  });

  it('ignores a drag that carries no files', () => {
    const onFiles = vi.fn();
    render(<UploadZone onFiles={onFiles} busy={false} />);
    const zone = screen.getByTestId('upload-zone');

    fireEvent.dragEnter(zone, { dataTransfer: { files: [], types: ['text/plain'] } });
    expect(zone.className).not.toContain('upload-zone--dragging');

    fireEvent.drop(zone, { dataTransfer: { files: [], types: ['text/plain'] } });
    expect(onFiles).not.toHaveBeenCalled();
  });

  it('highlights only while the drag is still over the zone', () => {
    render(<UploadZone onFiles={vi.fn()} busy={false} />);
    const zone = screen.getByTestId('upload-zone');

    fireEvent.dragEnter(zone, dropped([]));
    // Crossing a child fires enter/leave pairs the highlight must survive.
    fireEvent.dragEnter(zone, dropped([]));
    fireEvent.dragLeave(zone);
    expect(zone.className).toContain('upload-zone--dragging');

    fireEvent.dragLeave(zone);
    expect(zone.className).not.toContain('upload-zone--dragging');
  });

  it('hands picked files over and clears the picker so the same file can repeat', () => {
    const onFiles = vi.fn();
    render(<UploadZone onFiles={onFiles} busy={false} />);
    const picker = screen.getByLabelText('Choose files to upload') as HTMLInputElement;
    const file = new File(['x'], 'notes.txt');

    fireEvent.change(picker, { target: { files: [file] } });

    expect(onFiles).toHaveBeenCalledWith([file]);
    expect(picker.value).toBe('');
  });

  it('says so while an upload is running', () => {
    render(<UploadZone onFiles={vi.fn()} busy />);
    expect(screen.getByTestId('upload-zone-pick').textContent).toContain('UPLOADING');
  });
});
