package client

import "testing"

func TestDefaultSubjectsAreOlaresConvention(t *testing.T) {
	if SubjectUsers != "os.users" || SubjectGroups != "os.groups" {
		t.Fatalf("unexpected subjects: %q %q", SubjectUsers, SubjectGroups)
	}
	if DefaultStreamName != "os-stream" {
		t.Fatalf("unexpected stream name: %q", DefaultStreamName)
	}
	if len(DefaultSubjects) != 2 || DefaultSubjects[0] != SubjectUsers || DefaultSubjects[1] != SubjectGroups {
		t.Fatalf("unexpected default subjects: %v", DefaultSubjects)
	}
	for _, s := range DefaultSubjects {
		var covered bool
		for _, ss := range DefaultStreamSubjects {
			if ss == "os.>" {
				covered = true
			}
		}
		if !covered {
			t.Fatalf("subject %q not covered by stream subjects %v", s, DefaultStreamSubjects)
		}
	}
}
