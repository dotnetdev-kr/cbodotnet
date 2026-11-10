# SDK5 archived data and provider sources

`musl_legacy5_generated_source_inputs.validate` reads the actual source index
and archive. It requires the nine committed data/provider origins, original
commit objects, complete baseline Git trees and every recursive Gitlink child.
Every archived file must retain its original type, mode, bytes and Git blob.
The installer uses its existing six-patch recovery validator; the thirteen
data recipe files are then recovered and compared to their original source pins.

The aggregate validator must also run the complete combined source packet
verification. This part does not prove task execution, CLR provider loads,
publisher compilation, SDK consumers or whole producer admission. It performs
no source acquisition or runtime execution and does not activate a producer.

The focused tests use tiny synthetic Git objects and real index/TAR bytes.
They test source and Gitlink coverage, rebound hashes, altered modes, extra
members and allocation bounds. The existing installer guard is a fixture seam;
its own original-source and six-patch controls remain separately required.
