package reference

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/google/uuid"
	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/hyperledger/firefly-signer/pkg/abi"
	"github.com/kaleido-io/paladin/toolkit/pkg/pldapi"
	"github.com/kaleido-io/paladin/toolkit/pkg/pldclient"
	"github.com/kaleido-io/paladin/toolkit/pkg/query"
	"github.com/kaleido-io/paladin/toolkit/pkg/tkmsgs"
	"github.com/kaleido-io/paladin/toolkit/pkg/tktypes"
	"k8s.io/utils/ptr"
)

type TypeReferenceDoc struct {
	Example           []byte
	Description       []byte
	FieldDescriptions []byte
	SubFieldTables    []byte
}

type MethodReferenceDoc struct {
	Example     []byte
	Description []byte
	Params      []byte
	Return      []byte
}

// MethodDescription holds metadata about a method, including inputs and outputs.
type methodDescription struct {
	name    string
	inputs  []param
	outputs []param
}

// Param holds information about a method parameter or return type.
type param struct {
	name      string
	isList    bool
	isPointer bool
}

/*
 * This function generates a series of markdown pages to document Paladin types, and are
 * designed to be included in the docs. Each page is a []byte value in the map, and the
 * key is the file name of the page. To add additional pages, simply create an example
 * instance of the type you would like to document, then include that in the `types`
 * array which is passed to generateMarkdownPages(). Note: It is the responsibility of
 * some other caller function to actually write the bytes to disk.
 */

var allTypes = []interface{}{
	pldapi.IndexedEvent{},
	pldapi.TransactionInput{},
	pldapi.Transaction{},
	// pldapi.TransactionFull{}, // FIXME: The code needs a fix before uncommenting this (it looks like `field.Anonymous` is not handled properly)
	// pldapi.TransactionReceipt{}, // FIXME: The code needs a fix before uncommenting this (it looks like `field.Anonymous` is not handled properly)
	pldapi.PublicTx{},
	pldapi.StoredABI{
		ABI: abi.ABI{
			&abi.Entry{
				Type:            "function",
				Name:            "name",
				StateMutability: "pure",
			},
		},
		Hash: tktypes.Bytes32{},
	},
	query.QueryJSON{
		Limit: ptr.To(10),
		Sort:  []string{"field1 DESC", "field2"},
		Statements: query.Statements{
			Ops: query.Ops{
				Eq: []*query.OpSingleVal{
					{
						Op: query.Op{
							Field: "field1",
						},
						Value: tktypes.RawJSON(`{"value": 12345}`),
					},
					{
						Op: query.Op{
							Field:           "field12",
							Not:             true,
							CaseInsensitive: true,
						},
						Value: tktypes.RawJSON(`{"value": 12345}`),
					},
				},
				NEq: []*query.OpSingleVal{
					{
						Op: query.Op{
							Field: "field2",
						},
						Value: tktypes.RawJSON(`{"value": 12345}`),
					},
				},
				Like: []*query.OpSingleVal{
					{
						Op: query.Op{
							Field: "field3",
						},
						Value: tktypes.RawJSON(`{"value": 12345}`),
					},
				},
				LT: []*query.OpSingleVal{
					{
						Op: query.Op{
							Field: "field4",
						},
						Value: tktypes.RawJSON([]byte(`{"value": 12345}`)),
					},
				},
				LTE: []*query.OpSingleVal{
					{
						Op: query.Op{
							Field: "field5",
						},
						Value: tktypes.RawJSON([]byte(`{"value": 12345}`)),
					},
				},
				GT: []*query.OpSingleVal{
					{
						Op: query.Op{
							Field: "field6",
						},
						Value: tktypes.RawJSON([]byte(`{"value": 12345}`)),
					},
				},
				GTE: []*query.OpSingleVal{
					{
						Op: query.Op{
							Field: "field7",
						},
						Value: tktypes.RawJSON([]byte(`{"value": 12345}`)),
					},
				},
				In: []*query.OpMultiVal{
					{
						Op: query.Op{
							Field: "field8",
						},
						Values: []tktypes.RawJSON{[]byte(`{"value": 12345}`)},
					},
				},
				NIn: []*query.OpMultiVal{
					{
						Op: query.Op{
							Field: "field9",
						},
						Values: []tktypes.RawJSON{[]byte(`{"value": 12345}`)},
					},
				},
				Null: []*query.Op{
					{
						Field: "field10",
						Not:   true,
					},
					{
						Field: "field11",
					},
				},
			},
		},
	},
}
var allAPITypes = map[string][]interface{}{
	"ptx": {
		&pldclient.PTXTransactionDoc{},
	},
}
var allSimpleTypes = []interface{}{
	tktypes.Bytes32{},
	tktypes.HexBytes{},
	tktypes.EthAddress{},
	tktypes.HexUint256{},
	tktypes.HexInt256{},
	uuid.UUID{},
	tktypes.HexUint64(0),
	tktypes.Timestamp(0),
	tktypes.RawJSON([]byte{}),
	tktypes.PrivateIdentityLocator(""),
}

type docGenerator struct {
	pageToTypes map[string][]string
	typeToPage  map[string]string
}

func newDocGenerator() *docGenerator {
	return &docGenerator{
		pageToTypes: make(map[string][]string),
		typeToPage:  make(map[string]string),
	}
}

func GenerateObjectsReferenceMarkdown(ctx context.Context) (map[string][]byte, error) {
	d := newDocGenerator()

	types := allTypes
	simpleTypes := allSimpleTypes
	apiTypes := allAPITypes

	return d.generateMarkdownPages(ctx, types, simpleTypes, apiTypes, getRelativePath(4))
}

func (d *docGenerator) generateMarkdownPages(ctx context.Context, types, simpleTypes []interface{}, apiTypes map[string][]interface{}, outputPath string) (map[string][]byte, error) {
	markdownMap := make(map[string][]byte, len(types)+len(apiTypes)+1)

	typesPath := filepath.Join(outputPath, "types")
	apisPath := filepath.Join(outputPath, "apis")

	pageName := "simpletypes"
	markdownMap[filepath.Join(typesPath, pageName+".md")] = d.generateSimpleTypesMarkdown(ctx, simpleTypes, pageName, typesPath)

	// first add all pages to map
	for i, _ := range types {
		pageTitle := getType(types[i]).Name()
		d.pageToTypes[strings.ToLower(pageTitle)] = []string{}
	}

	// add types to their respective pages
	for i, o := range types {
		pageTitle := getType(types[i]).Name()
		pageName := strings.ToLower(pageTitle)

		// Page index starts at 1. Simple types will be the first page. Everything else comes after that.
		pageHeader := generatePageHeader(pageTitle)
		b := bytes.NewBuffer([]byte(pageHeader))
		markdown, err := d.generateObjectReferenceMarkdown(ctx, true, o, reflect.TypeOf(o), pageName, typesPath)
		if err != nil {
			return nil, err
		}
		b.Write(markdown)
		markdownMap[filepath.Join(typesPath, pageName+".md")] = b.Bytes()
	}

	// add api types
	for apiGroup, v := range apiTypes {
		for _, t := range v {
			pageTitle := fmt.Sprintf("API %s", apiGroup)
			pageName := strings.ToLower(apiGroup)

			// Page index starts at 1. Simple types will be the first page. Everything else comes after that.
			pageHeader := generatePageHeader(pageTitle)
			b := bytes.NewBuffer([]byte(pageHeader))
			markdown := d.generateMethodTypesMarkdown(ctx, t, apiGroup, apisPath)
			b.Write(markdown)

			markdownMap[filepath.Join(apisPath, pageName+".md")] = b.Bytes()
		}
	}

	return markdownMap, nil
}

func (d *docGenerator) generateMethodTypesMarkdown(ctx context.Context, methodType interface{}, apiGroup, outputPath string) []byte {
	methods := generateMethodDescriptions(methodType)

	b := bytes.NewBuffer([]byte{})
	for _, method := range methods {
		b.WriteString(fmt.Sprintf("## %s_%s\n\n", apiGroup, toLowerPrefix(method.name)))
		markdown, _ := d.generateMethodReferenceMarkdown(ctx, method, outputPath)
		b.Write(markdown)
	}
	return b.Bytes()
}

func (d *docGenerator) generateMethodReferenceMarkdown(ctx context.Context, method methodDescription, outputPath string) ([]byte, error) {
	methodReferenceDoc := MethodReferenceDoc{}

	des, err := getIncludeFile(ctx, outputPath, strings.ToLower(method.name))
	if err != nil {
		fmt.Printf("missing description for method %s\n", method.name)
	}
	methodReferenceDoc.Description = des

	// TODO: Add example???
	// typeReferenceDoc.Example = exampleJSON

	// buff is the main buffer where we will write the markdown for this page
	buff := bytes.NewBuffer([]byte{})

	if methodReferenceDoc.Description != nil {
		buff.Write(methodReferenceDoc.Description)
	}

	// **Add Parameters Section**
	if len(method.inputs) > 0 {
		buff.WriteString("### Parameters\n\n")
		for _, param := range method.inputs {
			buff.WriteString(fmt.Sprintf("- %s\n", d.getParamField(param)))
		}
		buff.WriteString("\n")
	}

	// **Add Return Section**
	if len(method.outputs) > 0 {
		buff.WriteString("### Returns\n\n")
		for _, param := range method.outputs {
			buff.WriteString(fmt.Sprintf("- %s\n", d.getParamField(param)))
		}
		buff.WriteString("\n")
	}

	// **Add Example Section if Available**
	if len(methodReferenceDoc.Example) > 0 {
		buff.WriteString("### Example\n\n```json\n")
		buff.Write(methodReferenceDoc.Example)
		buff.WriteString("\n```\n\n")
	}

	return buff.Bytes(), nil
}

func (d *docGenerator) getParamField(p param) string {
	listMarker := ""
	if p.isList {
		listMarker = "[]"
	}
	pldType := fmt.Sprintf("%s%s", p.name, listMarker)
	link := ""
	if fileName, ok := d.typeToPage[strings.ToLower(p.name)]; ok {
		link = fmt.Sprintf("../types/%s.md#%s", fileName, strings.ToLower(p.name))
	}
	if link != "" {
		pldType = fmt.Sprintf("[%s](%s)", pldType, link)
	}
	return pldType
}

// generateMethodDescriptions extracts metadata about all methods of a struct/interface.
func generateMethodDescriptions(example interface{}) []methodDescription {
	t := reflect.TypeOf(example)
	var methods []methodDescription

	// Iterate over all methods.
	for i := 0; i < t.NumMethod(); i++ {
		method := t.Method(i)
		if !method.IsExported() {
			continue
		}

		methodDesc := methodDescription{
			name:    method.Name,
			inputs:  extractParams(method.Type, true),
			outputs: extractParams(method.Type, false),
		}
		methods = append(methods, methodDesc)
	}
	return methods
}

// extractParams extracts input or output parameters from a method type.
func extractParams(funcType reflect.Type, isInput bool) []param {
	var params []param
	count := funcType.NumIn()
	start := 1 // Skip the first input (receiver)

	if !isInput {
		count = funcType.NumOut()
		start = 0 // For outputs, we start at 0
	}

	// Iterate over parameters.
	for j := start; j < count; j++ {
		var paramType reflect.Type
		if isInput {
			paramType = funcType.In(j)
		} else {
			paramType = funcType.Out(j)
		}

		// Use global filter logic to skip unwanted types.
		if shouldFilter(paramType) {
			continue
		}

		// FIXME: I'm not sure a pointer to a slice will parse correctly (because currently we first handle the slice and then the pointer)
		isList := paramType.Kind() == reflect.Slice
		if isList {
			paramType = paramType.Elem()
		}

		isPointer := paramType.Kind() == reflect.Ptr
		if isPointer {
			paramType = paramType.Elem()
		}

		// Store the parameter metadata.
		param := param{
			name:      paramType.Name(),
			isList:    isList,
			isPointer: isPointer,
		}
		params = append(params, param)
	}
	return params
}

func (d *docGenerator) generateSimpleTypesMarkdown(ctx context.Context, simpleTypes []interface{}, pageName, outputPath string) []byte {

	pageHeader := generatePageHeader("Simple Types")
	b := bytes.NewBuffer([]byte(pageHeader))
	for _, simpleType := range simpleTypes {
		b.WriteString(fmt.Sprintf("## %s\n\n", reflect.TypeOf(simpleType).Name()))
		markdown, _ := d.generateObjectReferenceMarkdown(ctx, true, nil, reflect.TypeOf(simpleType), pageName, outputPath)
		b.Write(markdown)
	}
	return b.Bytes()
}

func (d *docGenerator) generateObjectReferenceMarkdown(ctx context.Context, descRequired bool, example interface{}, t reflect.Type, pageName string, outputPath string) ([]byte, error) {
	typeReferenceDoc := TypeReferenceDoc{}

	if t.Kind() == reflect.Ptr {
		t = reflect.TypeOf(example).Elem()
	}
	// typeToPage is where we keep track of all the tables we've generated (recursively)
	// for creating hyperlinks within the markdown
	d.typeToPage[strings.ToLower(t.Name())] = pageName
	d.pageToTypes[pageName] = append(d.pageToTypes[pageName], t.Name())

	des, err := getIncludeFile(ctx, outputPath, strings.ToLower(t.Name()))
	if descRequired && err != nil {
		return nil, err
	}
	typeReferenceDoc.Description = des

	// Include an example JSON representation if we have one available
	if example != nil {
		exampleJSON, err := json.MarshalIndent(example, "", "    ")
		if err != nil {
			return nil, err
		}
		typeReferenceDoc.Example = exampleJSON
	}

	// If the type is a struct, look into each field inside it
	if t.Kind() == reflect.Struct {
		typeReferenceDoc.FieldDescriptions, typeReferenceDoc.SubFieldTables, err = d.generateFieldDescriptionsForStruct(ctx, t, pageName, outputPath)
		if err != nil {
			return nil, err
		}
	}

	// buff is the main buffer where we will write the markdown for this page
	buff := bytes.NewBuffer([]byte{})

	// If we only have one section, we will not write H3 headers
	sectionCount := 0
	if typeReferenceDoc.Description != nil {
		sectionCount++
	}
	if typeReferenceDoc.Example != nil {
		sectionCount++
	}
	if typeReferenceDoc.FieldDescriptions != nil {
		sectionCount++
	}

	if typeReferenceDoc.Description != nil {
		buff.Write(typeReferenceDoc.Description)
	}
	if len(typeReferenceDoc.Example) > 0 {
		if sectionCount > 1 {
			buff.WriteString("### Example\n\n```json\n")
		}
		buff.Write(typeReferenceDoc.Example)
		buff.WriteString("\n```\n\n")
	}
	if len(typeReferenceDoc.FieldDescriptions) > 0 {
		if sectionCount > 1 {
			buff.WriteString("### Field Descriptions\n\n")
		}
		buff.Write(typeReferenceDoc.FieldDescriptions)
		buff.WriteString("\n")
	}

	if len(typeReferenceDoc.SubFieldTables) > 0 {
		buff.Write(typeReferenceDoc.SubFieldTables)
	}

	return buff.Bytes(), nil
}

func (d *docGenerator) generateFieldDescriptionsForStruct(ctx context.Context, t reflect.Type, pageName string, outputPath string) ([]byte, []byte, error) {
	var err error

	fieldDescriptionsBytes := []byte{}
	// subFieldBuff is where we write any additional tables for sub fields that may be on this struct
	subFieldBuff := bytes.NewBuffer([]byte{})
	if t.NumField() > 0 {
		// Write the table to a temporary buffer - we will throw it away if there are no
		// public JSON serializable fields on the struct
		tableRowCount := 0
		tableBuff := bytes.NewBuffer([]byte{})
		tableBuff.WriteString("| Field Name | Description | Type |\n")
		tableBuff.WriteString("|------------|-------------|------|\n")
		tableRowCount, err = d.writeStructFields(ctx, t, pageName, outputPath, subFieldBuff, tableBuff, tableRowCount)
		if err != nil {
			return nil, nil, err
		}
		if tableRowCount > 0 {
			fieldDescriptionsBytes = tableBuff.Bytes()
		}
	}

	return fieldDescriptionsBytes, subFieldBuff.Bytes(), err
}

func (d *docGenerator) writeStructFields(ctx context.Context, t reflect.Type, pageName string, outputPath string, subFieldBuff, tableBuff *bytes.Buffer, tableRowCount int) (int, error) {
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		jsonTag := field.Tag.Get("json")
		structTag := field.Tag.Get("docstruct")
		excludeTag := field.Tag.Get("docexclude")

		// If this is a nested struct, we need to recurse into it
		if field.Anonymous {
			var err error
			tableRowCount, err = d.writeStructFields(ctx, field.Type, pageName, outputPath, subFieldBuff, tableBuff, tableRowCount)
			if err != nil {
				return tableRowCount, err
			}
			continue
		}

		// If the field is specifically excluded, or doesn't have a json tag, skip it
		if excludeTag != "" || jsonTag == "" || jsonTag == "-" {
			continue
		}

		jsonFieldName := strings.Split(jsonTag, ",")[0]
		messageKeyName := fmt.Sprintf("%s.%s", structTag, jsonFieldName)
		description := i18n.Expand(ctx, i18n.MessageKey(messageKeyName))
		if description == messageKeyName {
			return tableRowCount, i18n.NewError(ctx, tkmsgs.MsgFieldDescriptionMissing, jsonFieldName, t.Name())
		}

		isArray := false

		fieldType := field.Type
		pldType := fieldType.Name()

		if fieldType.Kind() == reflect.Slice {
			fieldType = fieldType.Elem()
			pldType = fieldType.Name()
			isArray = true
		}

		if fieldType.Kind() == reflect.Ptr {
			fieldType = fieldType.Elem()
			pldType = fieldType.Name()
		}

		if isArray {
			pldType = fmt.Sprintf("%s[]", pldType)
		}

		pldType = fmt.Sprintf("`%s`", pldType)

		isStruct := fieldType.Kind() == reflect.Struct
		isEnum := strings.ToLower(fieldType.Name()) == "docenum"

		link := ""
		if isEnum {
			pldType = generateEnumList(field)
		} else if p, ok := d.typeToPage[strings.ToLower(fieldType.Name())]; ok && p != pageName {
			link = fmt.Sprintf("%s.md#%s", p, strings.ToLower(fieldType.Name()))
		} else if isStruct {
			link = fmt.Sprintf("#%s", strings.ToLower(fieldType.Name()))
		}

		if link != "" {
			pldType = fmt.Sprintf("[%s](%s)", pldType, link)

			// Generate the table for the sub type
			_, typeAlreadyGenerated := d.typeToPage[strings.ToLower(fieldType.Name())]
			_, page := d.pageToTypes[strings.ToLower(fieldType.Name())]

			if isStruct && !typeAlreadyGenerated && !page {
				subFieldBuff.WriteString(fmt.Sprintf("## %s\n\n", fieldType.Name()))
				subFieldMarkdown, _ := d.generateObjectReferenceMarkdown(ctx, false, nil, fieldType, pageName, outputPath)
				subFieldBuff.Write(subFieldMarkdown)
				subFieldBuff.WriteString("\n")
			}
		}

		tableBuff.WriteString(fmt.Sprintf("| `%s` | %s | %s |\n", jsonFieldName, description, pldType))
		tableRowCount++
	}
	return tableRowCount, nil
}

func generatePageHeader(pageTitle string) string {
	return fmt.Sprintf(`---
title: %s
---
`, pageTitle)
}
