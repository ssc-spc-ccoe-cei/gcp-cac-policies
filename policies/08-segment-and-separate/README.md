# Guardrail #08 - Segment and Separate

Segment and separate information based on sensitivity of information.

**Key Considerations:**

- [ ] Develop a target network security design that considers segmentation via network security zones, in alignment with ITSG-22 and ITSG-38.
- [ ] Implement increased levels of protection for management interfaces.

## Policies

- [08-file-check.rego](./08-file-check.rego)

## 08-file-check.rego

Check for the presence of one (1) file in the `guardrail-08` Google Cloud Storage Bucket:

- Network Architecture diagram

### Policy Flow Diagram

![08-file-check](../../policy_diagrams/08-file-check.png "08-file-check")

### Compliant

To ensure the policy is `COMPLIANT` you should ensure that the one (1) file required is present in the `guardrail-08` Google Cloud Storage Bucket:

- Network Architecture diagram

>NOTE: Due to not being able to guarantee what name the file(s) will be, this policy will only check that the number of files present exceeds the minimum number required (including the default instructions.txt file).

### Non-Compliant

If this policy is found to be `NON-COMPLIANT` you should ensure that the one (1) file required is present in the `guardrail-08` Google Cloud Storage Bucket:

- Network Architecture diagram

You may also want to ensure that the default instructions.txt file is still present as well.

Finally, you may need to alter the `required_file_count` value inside `08-file-check.rego` to set what the minimum required number of files should be (including the default instructions.txt).
