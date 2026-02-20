from sigma.pipelines.hawk import hawk_pipeline, pipelines
from sigma.processing.pipeline import ProcessingPipeline


def test_pipeline_registry_exposes_hawk_pipeline() -> None:
    assert "hawk_pipeline" in pipelines
    pipeline = pipelines["hawk_pipeline"]()
    assert isinstance(pipeline, ProcessingPipeline)


def test_hawk_pipeline_metadata() -> None:
    pipeline = hawk_pipeline()
    assert pipeline.name == "hawk pipeline"
    assert "hawk" in pipeline.allowed_backends
