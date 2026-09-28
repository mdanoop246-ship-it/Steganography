import numpy as np
from skimage.metrics import structural_similarity

def image_metrics(a, b):
    x = np.asarray(a.convert("RGB"), dtype=np.float32)
    y = np.asarray(b.convert("RGB"), dtype=np.float32)
    mse = float(np.mean((x-y)**2))
    psnr = float("inf") if mse == 0 else float(10*np.log10((255**2)/mse))
    ssim = float(structural_similarity(x.astype(np.uint8), y.astype(np.uint8), channel_axis=2, data_range=255))
    return {"mse": round(mse, 6), "psnr": round(psnr, 3), "ssim": round(ssim, 6)}
