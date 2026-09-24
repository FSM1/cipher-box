/**
 * PROTOTYPE — throwaway. Four variants of the share dialog under the
 * link-first model, switchable via `?variant=A|B|C|D` on the files route.
 * Fed by an in-memory stub; it calls no engine and no facade.
 */
import { useState } from 'react';
import { Modal } from '../../ui/Modal';
import { SharePrototypeStatePanel } from './SharePrototypeStatePanel';
import { useSharePrototypeStore, type ProtoAction } from './SharePrototypeStore';
import { SharePrototypeVariantA } from './SharePrototypeVariantA';
import { SharePrototypeVariantB } from './SharePrototypeVariantB';
import { SharePrototypeVariantC } from './SharePrototypeVariantC';
import { SharePrototypeVariantD } from './SharePrototypeVariantD';
import type { ProtoVariant } from './SharePrototypeVariant';
import './SharePrototype.css';

export function SharePrototypeDialog({
  folderName,
  variant,
  onClose,
}: {
  folderName: string;
  variant: ProtoVariant;
  onClose: () => void;
}) {
  const [state, rawDispatch] = useSharePrototypeStore();
  // A preset remounts the variant so its own local step/panel state resets too.
  const [generation, setGeneration] = useState(0);
  const dispatch = (action: ProtoAction) => {
    rawDispatch(action);
    if (action.type === 'preset') setGeneration((value) => value + 1);
  };

  const Variant = {
    A: SharePrototypeVariantA,
    B: SharePrototypeVariantB,
    C: SharePrototypeVariantC,
    D: SharePrototypeVariantD,
  }[variant];

  return (
    <Modal onClose={onClose} title={`share ${folderName}`} className="modal-backdrop--proto">
      <Variant key={`${variant}-${generation}`} state={state} dispatch={dispatch} />
      <div className="dialog-actions">
        <button type="button" className="dialog-button" onClick={onClose}>
          done
        </button>
      </div>
      <SharePrototypeStatePanel state={state} dispatch={dispatch} />
    </Modal>
  );
}
