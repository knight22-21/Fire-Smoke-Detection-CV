from ultralytics import YOLO

def main():
    # Load YOLOv8 model
    model = YOLO('yolov8s.pt')

    # Train the model
    model.train(
        data=r"C:\Users\Krish\cv\Fire-Smoke-Detector\fire_smoke.yaml",
        epochs=5,
        imgsz=640,
        batch=16,
        project="fire_smoke_detector",
        name="yolov8_run",
        device=0
    )

    # Evaluate on validation set
    print("\nEvaluating model on validation data...")
    results_val = model.val()
    print(f"Validation Results: {results_val}")

    # Evaluate on test set with metrics
    print("\nEvaluating model on test data...")
    results_test = model.val(split='test')
    print(f"Test Results: {results_test}")

    print("\nRunning prediction on test images...")
    preds = model.predict(source=r"C:\Users\Krish\cv\Fire-Smoke-Detector\dataset\test\images", imgsz=640, conf=0.25, save=True)
    print("Prediction complete. Results saved in runs/detect/")

if __name__ == "__main__":
    main()
